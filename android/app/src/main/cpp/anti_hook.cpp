/**
 * CyberGuard Anti-Hooking Detection (Android NDK)
 *
 * ## Why C++ for hook detection:
 * Frida and Xposed work by injecting code into the process. If we detect
 * hooks from Kotlin/Java (which runs inside ART), the detection code itself
 * can be hooked to return false. C++ detection runs as raw machine code —
 * much harder to intercept without being detected.
 *
 * ## Detection methods:
 *
 * ### 1. /proc/self/maps scanning
 * Every loaded library appears in /proc/self/maps. Frida injects
 * "frida-agent" or "frida-gadget" which show up as mapped memory regions.
 * Xposed injects "XposedBridge.jar". We scan for these signatures.
 *
 * ### 2. Frida port detection
 * frida-server listens on TCP port 27042 by default. We try to connect
 * to localhost:27042. If the connection succeeds, Frida is running.
 * We also scan nearby ports (27042-27052) since users can change it.
 *
 * ### 3. Inline hook detection (ARM64)
 * Hooking frameworks replace the first bytes of a function with a branch
 * instruction that redirects to the hook handler. On ARM64:
 * - LDR + BR pattern: Load address into register, then branch
 * - B/BL instruction: Direct branch to hook trampoline
 * We check the prologues of critical functions for these patterns.
 *
 * ### 4. Thread name scanning
 * Frida creates threads named "gmain", "gdbus", "gum-js-loop".
 * We scan /proc/self/task/{tid}/comm for these names.
 */

#include <jni.h>
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define LOG_TAG "CyberGuardAntiHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// ─── Known hooking framework library signatures ───
// These strings appear in /proc/self/maps when frameworks are injected.
// ALL LOWERCASE — we convert /proc/self/maps lines to lowercase before matching.
static const char* HOOK_LIBRARY_SIGNATURES[] = {
    // Frida
    "frida",
    "frida-agent",
    "frida-gadget",
    "libfrida",
    // Xposed
    "xposedbridge",
    "xposed",
    "libxposed",
    "de.robv.android.xposed",
    // LSPosed (modern Xposed successor)
    "lspd",
    "lsposed",
    "liblspd",
    // Cydia Substrate
    "substrate",
    "libsubstrate",
    "substratehook",
    // Epic (Android hooking library)
    "libepic",
    // General hooking artifacts
    "libgadget",
    "libhook",
};
static const int HOOK_SIGNATURE_COUNT = sizeof(HOOK_LIBRARY_SIGNATURES) / sizeof(HOOK_LIBRARY_SIGNATURES[0]);

// ─── Frida-specific thread names ───
// Frida creates GLib main loop threads with these names.
static const char* FRIDA_THREAD_NAMES[] = {
    "gmain",
    "gdbus",
    "gum-js-loop",
    "pool-frida",
    "frida",
};
static const int FRIDA_THREAD_COUNT = sizeof(FRIDA_THREAD_NAMES) / sizeof(FRIDA_THREAD_NAMES[0]);

/**
 * Scan /proc/self/maps for hooking framework libraries.
 *
 * /proc/self/maps format:
 *   address           perms offset  dev   inode   pathname
 *   7f1234000-7f1235000 r-xp 00000000 08:01 123456 /data/local/tmp/frida-agent.so
 *
 * We read line by line and check if any line contains a known signature.
 */
static bool scan_maps_for_hooks() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        // Convert to lowercase for case-insensitive matching
        char lower[512];
        int i = 0;
        for (; line[i] && i < 511; i++) {
            lower[i] = (line[i] >= 'A' && line[i] <= 'Z') ? line[i] + 32 : line[i];
        }
        lower[i] = '\0';

        for (int j = 0; j < HOOK_SIGNATURE_COUNT; j++) {
            if (strstr(lower, HOOK_LIBRARY_SIGNATURES[j]) != nullptr) {
                LOGW("Hook library detected in maps: %s", line);
                fclose(maps);
                return true;
            }
        }
    }

    fclose(maps);
    return false;
}

/**
 * Check if Frida server is listening on its default port range.
 *
 * frida-server binds to 0.0.0.0:27042 by default. We attempt a
 * non-blocking connect to localhost on ports 27042-27052.
 * A successful connection (or connection in progress) indicates Frida.
 *
 * We use a non-blocking socket with a very short timeout (50ms) to
 * avoid slowing down the monitoring loop.
 */
static bool check_frida_port() {
    for (int port = 27042; port <= 27052; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Set non-blocking with short timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; // 50ms timeout
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);

        if (result == 0) {
            LOGW("Frida port detected: %d", port);
            return true;
        }
    }
    return false;
}

/**
 * Scan /proc/self/task/{tid}/comm for Frida thread names.
 *
 * Frida injects threads into the target process for its GLib event loop.
 * These threads have distinctive names like "gmain", "gdbus", "gum-js-loop".
 *
 * /proc/self/task/ lists all threads of the current process.
 * Each thread has a /comm file containing the thread name (max 16 chars).
 */
static bool scan_frida_threads() {
    DIR* task_dir = opendir("/proc/self/task");
    if (!task_dir) return false;

    struct dirent* entry;
    char comm_path[128];
    char comm_name[32];
    int frida_thread_count = 0;

    while ((entry = readdir(task_dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);

        int fd = open(comm_path, O_RDONLY);
        if (fd < 0) continue;

        ssize_t n = read(fd, comm_name, sizeof(comm_name) - 1);
        close(fd);

        if (n <= 0) continue;
        comm_name[n] = '\0';

        // Strip trailing newline
        if (n > 0 && comm_name[n - 1] == '\n') {
            comm_name[n - 1] = '\0';
        }

        // Check against known Frida thread names
        for (int i = 0; i < FRIDA_THREAD_COUNT; i++) {
            if (strcmp(comm_name, FRIDA_THREAD_NAMES[i]) == 0) {
                frida_thread_count++;
                break;
            }
        }
    }

    closedir(task_dir);

    // Require at least 2 Frida-like threads to reduce false positives.
    // A normal app might have one "gmain" thread, but Frida creates multiple.
    if (frida_thread_count >= 2) {
        LOGW("Frida threads detected: %d suspicious threads", frida_thread_count);
        return true;
    }

    return false;
}

/**
 * Check for inline hooks on critical libc functions.
 *
 * ## How inline hooking works on ARM64:
 *
 * Normal function prologue:
 *   STP X29, X30, [SP, #-0x10]!   → Save frame pointer and return address
 *   MOV X29, SP                    → Set up frame pointer
 *
 * Hooked function prologue:
 *   LDR X16, [PC, #8]             → Load absolute address
 *   BR X16                         → Branch to hook handler
 *   <64-bit address>               → Address of the hook
 *
 * We check if the first instruction of critical functions (open, read, etc.)
 * looks like a hook trampoline instead of a normal prologue.
 *
 * ## ARM64 instruction encoding:
 * - LDR Xn, [PC, #imm]: 0x58000000 | (imm >> 2) << 5 | Rn
 * - BR Xn: 0xD61F0000 | (Rn << 5)
 * - B #offset: 0x14000000 | (offset >> 2)
 */
static bool check_inline_hooks() {
    // Functions that hooking frameworks commonly target
    const char* critical_functions[] = {
        "open",     // File access (used for /proc scanning)
        "read",     // Reading /proc files
        "connect",  // Network connections (Frida port check)
        "fopen",    // C file I/O
        "strcmp",    // String comparison (bypass checks)
    };

    for (const char* func_name : critical_functions) {
        void* func_ptr = dlsym(RTLD_DEFAULT, func_name);
        if (!func_ptr) continue;

        // Read the first 4 bytes (one ARM64 instruction)
        uint32_t first_instruction;
        memcpy(&first_instruction, func_ptr, sizeof(uint32_t));

#if defined(__aarch64__)
        // Check for LDR Xn, [PC, #imm] pattern (0x58xxxxxx)
        // This is the most common Frida trampoline pattern
        if ((first_instruction & 0xFF000000) == 0x58000000) {
            LOGW("Inline hook detected on %s: LDR trampoline (0x%08X)", func_name, first_instruction);
            return true;
        }

        // Check for unconditional branch B #offset (0x14xxxxxx or 0x17xxxxxx)
        // Large offset branches are suspicious for function prologues
        uint32_t b_mask = first_instruction & 0xFC000000;
        if (b_mask == 0x14000000 || b_mask == 0x94000000) {
            // B or BL to a far address — could be a hook
            int32_t offset = (int32_t)(first_instruction & 0x03FFFFFF);
            if (offset < 0) offset |= (int32_t)0xFC000000; // Sign extend
            // If jumping more than 4KB, it's suspicious for a function prologue
            if (offset > 1024 || offset < -1024) {
                LOGW("Inline hook detected on %s: far branch (0x%08X, offset: %d)", func_name, first_instruction, offset);
                return true;
            }
        }
#elif defined(__arm__)
        // ARM32: Check for LDR PC, [PC, #-4] pattern
        if ((first_instruction & 0xFFFFF000) == 0xE51FF000) {
            LOGW("Inline hook detected on %s: LDR PC trampoline (0x%08X)", func_name, first_instruction);
            return true;
        }
#elif defined(__i386__) || defined(__x86_64__)
        // x86/x64: Check for JMP (0xE9) or INT3 (0xCC) at function start
        uint8_t first_byte = *(uint8_t*)func_ptr;
        if (first_byte == 0xE9 || first_byte == 0xCC) {
            LOGW("Inline hook detected on %s: JMP/INT3 (0x%02X)", func_name, first_byte);
            return true;
        }
#endif
    }

    return false;
}

/**
 * Check for Magisk hide or Zygisk modules.
 *
 * Magisk's "DenyList" (formerly MagiskHide) hides root from specific apps.
 * However, it has telltale signs:
 * - /proc/self/mounts shows magisk-related mount points
 * - Environment variables may contain magisk paths
 */
static bool check_magisk_traces() {
    FILE* mounts = fopen("/proc/self/mounts", "r");
    if (!mounts) return false;

    char line[512];
    const char* magisk_indicators[] = {
        "magisk",
        "/sbin/.magisk",
        "tmpfs /system/",
        "tmpfs /vendor/",
    };

    while (fgets(line, sizeof(line), mounts)) {
        for (const char* indicator : magisk_indicators) {
            if (strstr(line, indicator) != nullptr) {
                LOGW("Magisk trace in mounts: %s", line);
                fclose(mounts);
                return true;
            }
        }
    }

    fclose(mounts);
    return false;
}

/**
 * Check for root binary (su) in common paths using direct syscalls.
 *
 * We use access() instead of stat() because:
 * 1. It's a single syscall (faster)
 * 2. We only need to know if the file exists, not its metadata
 * 3. Harder to hook a single syscall than a library function
 */
static bool check_su_binary() {
    const char* su_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        // Magisk
        "/system/xbin/magisk",
        "/sbin/magisk",
        "/sbin/.magisk",
        // KernelSU
        "/data/adb/ksud",
        "/data/adb/ksu",
    };

    for (const char* path : su_paths) {
        if (access(path, F_OK) == 0) {
            LOGW("Root binary found: %s", path);
            return true;
        }
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════
// JNI EXPORTS — Called from Kotlin via SecurityBridge
// ═══════════════════════════════════════════════════════════════

extern "C" {

/**
 * Comprehensive hook detection.
 * Returns a bitmask of detection results:
 *   Bit 0 (0x01): Maps scan found hooking library
 *   Bit 1 (0x02): Frida port is open
 *   Bit 2 (0x04): Frida threads detected
 *   Bit 3 (0x08): Inline hooks detected
 *
 * Returning a bitmask lets Kotlin know WHICH detection method triggered,
 * useful for logging and forensics.
 */
JNIEXPORT jint JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeDetectHooks(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    int result = 0;

    if (scan_maps_for_hooks())  result |= 0x01;
    if (check_frida_port())     result |= 0x02;
    if (scan_frida_threads())   result |= 0x04;
    if (check_inline_hooks())   result |= 0x08;

    return result;
}

/**
 * Root detection at native level.
 * Returns a bitmask:
 *   Bit 0 (0x01): su binary found
 *   Bit 1 (0x02): Magisk traces in mounts
 */
JNIEXPORT jint JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeDetectRoot(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    int result = 0;

    if (check_su_binary())     result |= 0x01;
    if (check_magisk_traces()) result |= 0x02;

    return result;
}

} // extern "C"
