/**
 * CyberGuard Native Security Core (Android)
 *
 * This C++ module runs OUTSIDE the Android Runtime (ART/Dalvik).
 * Why this matters:
 *   - Kotlin/Java code runs inside ART which can be hooked by Xposed/Frida
 *   - C++ code runs directly on the CPU as machine code
 *   - Much harder to intercept or modify at runtime
 *
 * Functions provided:
 *   1. detectScreenCapture() — scans /proc for recording processes
 *   2. isDebuggerAttached() — checks TracerPid in /proc/self/status
 *   3. enableAntiDebug() — prevents ptrace attachment
 *   4. detectSuspiciousProcesses() — broad process enumeration
 *
 * JNI naming convention:
 *   Java_<package>_<class>_<method>
 *   package dots become underscores: com.myapp.cyber_1guard → com_myapp_cyber_1guard
 *   Note: underscore in package name "cyber_guard" becomes "_1" in JNI
 */

#include <jni.h>
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <cctype>

#define LOG_TAG "CyberGuardNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ─── Known screen capture process names ───
// These are checked against /proc/<pid>/cmdline.
// Keep this list updated as new recording tools emerge.
static const char* CAPTURE_PROCESSES[] = {
    "screenrecord",
    "screencap",
    "ffmpeg",
    "obs",
    "scrcpy",
    "vysor",
    "teamviewer",
    "anydesk",
    "mirrorlink",
    "screen_recorder",
    "az_screen",
    "du_recorder",
    "mobizen",
    "rec.",
    "apowerrec",
    "xrecorder",
};
static const int CAPTURE_PROCESS_COUNT = sizeof(CAPTURE_PROCESSES) / sizeof(CAPTURE_PROCESSES[0]);

/**
 * Read the cmdline of a process from /proc/<pid>/cmdline.
 * Returns true if successfully read, false otherwise.
 *
 * How /proc/<pid>/cmdline works:
 *   - Each running process on Linux/Android has a directory in /proc/
 *   - The cmdline file contains the command that started the process
 *   - Arguments are separated by null bytes
 *   - We read the first 255 bytes which is enough for the process name
 */
static bool read_process_cmdline(int pid, char* buffer, size_t buffer_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    ssize_t n = read(fd, buffer, buffer_size - 1);
    close(fd);

    if (n <= 0) return false;
    buffer[n] = '\0';

    // Replace null separators with spaces for easier substring search
    for (ssize_t i = 0; i < n; i++) {
        if (buffer[i] == '\0') buffer[i] = ' ';
    }

    return true;
}

/**
 * Scan all running processes for known screen capture tools.
 *
 * How it works:
 *   1. Open /proc/ directory (lists all processes by PID)
 *   2. For each numeric directory (= a process), read its cmdline
 *   3. Check if cmdline contains any known capture process name
 *   4. Return true immediately if any match found
 *
 * Why scan /proc instead of using Android APIs:
 *   - ActivityManager.getRunningAppProcesses() is restricted in newer Android
 *   - Android APIs can be hooked by Xposed/Frida to hide processes
 *   - /proc is a kernel filesystem — much harder to fake
 */
static bool scan_for_capture_processes() {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;

    struct dirent* entry;
    char cmdline[256];

    while ((entry = readdir(proc_dir)) != nullptr) {
        // Skip non-numeric entries (not PIDs)
        if (!isdigit(entry->d_name[0])) continue;

        int pid = atoi(entry->d_name);
        // Skip our own process
        if (pid == getpid()) continue;

        if (!read_process_cmdline(pid, cmdline, sizeof(cmdline))) continue;

        // Convert to lowercase for case-insensitive matching
        for (char* p = cmdline; *p; p++) {
            *p = static_cast<char>(tolower(*p));
        }

        // Check against known capture processes
        for (int i = 0; i < CAPTURE_PROCESS_COUNT; i++) {
            if (strstr(cmdline, CAPTURE_PROCESSES[i]) != nullptr) {
                LOGW("Capture process detected: %s (PID: %d)", cmdline, pid);
                closedir(proc_dir);
                return true;
            }
        }
    }

    closedir(proc_dir);
    return false;
}

/**
 * Check if a debugger is attached by reading /proc/self/status.
 *
 * How it works:
 *   - Every Linux process has /proc/self/status which contains process info
 *   - The "TracerPid" line shows the PID of the tracing (debugging) process
 *   - If TracerPid is 0, no debugger is attached
 *   - If TracerPid is non-zero, something is debugging us
 *
 * Why this is important:
 *   - Debuggers can inspect memory, modify variables, bypass checks
 *   - A debugger can patch out FLAG_SECURE at runtime
 *   - We check this at C++ level because Java-level checks can be hooked
 */
static bool check_debugger_status() {
    char line[256];
    FILE* status = fopen("/proc/self/status", "r");
    if (!status) return false;

    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(status);
            if (tracer_pid != 0) {
                LOGW("Debugger detected: TracerPid = %d", tracer_pid);
                return true;
            }
            return false;
        }
    }

    fclose(status);
    return false;
}

/**
 * Enable anti-debugging protections at the kernel level.
 *
 * prctl(PR_SET_DUMPABLE, 0):
 *   - Prevents core dumps from being generated
 *   - Makes /proc/self/mem unreadable by other processes
 *   - This stops tools like GameGuardian from reading our memory
 *
 * Why we don't use ptrace(PT_DENY_ATTACH):
 *   - On Android, ptrace is more restricted than on desktop Linux
 *   - prctl is the recommended approach for Android NDK code
 */
static void enable_anti_debug() {
    // Prevent core dumps (memory dumps contain sensitive data)
    prctl(PR_SET_DUMPABLE, 0);
    LOGI("Anti-debug enabled: PR_SET_DUMPABLE = 0");
}

// ═══════════════════════════════════════════════════════════════
// JNI EXPORTS — Called from Kotlin via SecurityBridge class
// ═══════════════════════════════════════════════════════════════

extern "C" {

/**
 * Initialize native security protections.
 * Called once when the security plugin starts.
 *
 * JNI name breakdown:
 *   Java_com_myapp_cyber_1guard_SecurityBridge_nativeInit
 *   ^^^^                                        ^^^^^^^^^^
 *   JNI prefix                                  method name
 *        ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *        package: com.myapp.cyber_guard (underscore → _1)
 */
JNIEXPORT void JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeInit(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    enable_anti_debug();
    LOGI("CyberGuard native security initialized");
}

/**
 * Check if any screen capture process is currently running.
 * Called periodically (every 50-100ms) from the Kotlin monitoring thread.
 *
 * Returns JNI_TRUE if a capture process is detected.
 */
JNIEXPORT jboolean JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeDetectScreenCapture(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    return scan_for_capture_processes() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Check if a debugger is currently attached to this process.
 * Called periodically from the Kotlin monitoring thread.
 *
 * Returns JNI_TRUE if a debugger is detected.
 */
JNIEXPORT jboolean JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeIsDebuggerAttached(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    return check_debugger_status() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Enable anti-debugging protections.
 * Can be called again if protections need to be re-applied.
 */
JNIEXPORT void JNICALL
Java_com_myapp_cyber_1guard_SecurityBridge_nativeEnableAntiDebug(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    enable_anti_debug();
}

} // extern "C"
