package com.myapp.cyber_guard

import android.os.Debug
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Background security monitoring thread.
 *
 * ## How it works:
 * Runs a daemon thread that periodically checks for threats using BOTH
 * Kotlin-level APIs and native C++ functions:
 *
 * ```
 * Loop (every intervalMs):
 *   ├── Fast checks (every iteration):
 *   │   ├── C++ nativeDetectScreenCapture() → scan /proc for recording apps
 *   │   ├── C++ nativeIsDebuggerAttached()  → check TracerPid
 *   │   ├── C++ nativeDetectHooks()         → Frida/Xposed/Substrate
 *   │   └── Kotlin Debug.isDebuggerConnected() → JVM debugger
 *   │
 *   └── Slow checks (every 10th iteration):
 *       ├── Kotlin RootDetector  → 7-signal root detection
 *       ├── Kotlin EmulatorDetector → build props, hardware, sensors
 *       └── Kotlin MemoryProtection → DEX hash, library count, injection
 * ```
 *
 * ## Check frequency rationale:
 * - Fast checks: screen capture and debugger can attach at any moment,
 *   so we check every iteration (~100ms). These are cheap /proc reads.
 * - Slow checks: root/emulator/integrity don't change at runtime,
 *   so checking every ~1s is sufficient. These involve file I/O,
 *   package manager queries, and crypto hashes.
 *
 * ## Thread safety:
 * - Uses AtomicBoolean for start/stop control and detection flags
 * - EventEmitter handles thread-safe posting to main thread
 * - SecurityBridge native methods are thread-safe (read-only /proc access)
 */
class SecurityMonitor(
    private val bridge: SecurityBridge,
    private val eventEmitter: SecurityEventEmitter,
    private val intervalMs: Long = 100,
    private val rootDetector: RootDetector? = null,
    private val emulatorDetector: EmulatorDetector? = null,
    private val memoryProtection: MemoryProtection? = null,
) {
    companion object {
        private const val TAG = "SecurityMonitor"
        private const val SLOW_CHECK_INTERVAL = 10
    }

    private val isRunning = AtomicBoolean(false)
    private var monitorThread: Thread? = null

    // Track what we've already detected to avoid spamming events.
    // Once a threat is detected, we emit ONCE and set the flag.
    private var captureDetected = AtomicBoolean(false)
    private var debuggerDetected = AtomicBoolean(false)
    private var hookDetected = AtomicBoolean(false)
    private var rootDetected = AtomicBoolean(false)
    private var emulatorDetected = AtomicBoolean(false)
    private var integrityViolated = AtomicBoolean(false)

    /**
     * Start the background monitoring thread.
     *
     * The thread runs as a daemon so it doesn't prevent app shutdown.
     * Priority is set to MAX to ensure security checks aren't delayed
     * by other background work.
     */
    fun start() {
        if (isRunning.getAndSet(true)) return // Already running

        monitorThread = Thread {
            Log.i(TAG, "Security monitoring started (interval: ${intervalMs}ms)")

            var iteration = 0L

            while (isRunning.get()) {
                try {
                    // Fast checks — every iteration
                    checkScreenCapture()
                    checkDebugger()
                    checkHooks()

                    // Slow checks — every Nth iteration
                    if (iteration % SLOW_CHECK_INTERVAL == 0L) {
                        checkRoot()
                        checkEmulator()
                        checkIntegrity()
                    }

                    iteration++
                    Thread.sleep(intervalMs)
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Security check error: ${e.message}")
                }
            }

            Log.i(TAG, "Security monitoring stopped")
        }.apply {
            isDaemon = true
            priority = Thread.MAX_PRIORITY
            name = "CyberGuard-Monitor"
            start()
        }
    }

    /** Stop the monitoring thread. */
    fun stop() {
        isRunning.set(false)
        monitorThread?.interrupt()
        monitorThread = null
    }

    // ─── Fast checks ───

    private fun checkScreenCapture() {
        try {
            val isCapturing = bridge.nativeDetectScreenCapture()

            if (isCapturing && !captureDetected.getAndSet(true)) {
                eventEmitter.emit(
                    type = "screenCapture",
                    severity = "high",
                    metadata = mapOf("method" to "native_process_scan")
                )
            } else if (!isCapturing) {
                captureDetected.set(false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Native capture detection error: ${e.message}")
        }
    }

    private fun checkDebugger() {
        try {
            val jvmDebugger = Debug.isDebuggerConnected()
            val nativeDebugger = bridge.nativeIsDebuggerAttached()

            if ((jvmDebugger || nativeDebugger) && !debuggerDetected.getAndSet(true)) {
                val method = when {
                    jvmDebugger && nativeDebugger -> "jvm_and_native"
                    jvmDebugger -> "jvm_debugger"
                    else -> "native_tracer"
                }

                eventEmitter.emit(
                    type = "debuggerAttached",
                    severity = "critical",
                    metadata = mapOf("method" to method)
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Debugger detection error: ${e.message}")
        }
    }

    /**
     * Check for hooking frameworks via native C++ detection.
     *
     * The C++ layer checks:
     * 1. /proc/self/maps for Frida/Xposed/Substrate library names
     * 2. TCP port 27042-27052 (Frida server default)
     * 3. Thread names (gmain, gdbus = Frida's GLib event loop)
     * 4. Inline hooks on libc functions (ARM64 LDR+BR trampolines)
     *
     * Returns a bitmask so we know WHICH detection method triggered.
     */
    private fun checkHooks() {
        try {
            val hookResult = bridge.nativeDetectHooks()

            if (hookResult != 0 && !hookDetected.getAndSet(true)) {
                val methods = mutableListOf<String>()
                if (hookResult and 0x01 != 0) methods.add("maps_scan")
                if (hookResult and 0x02 != 0) methods.add("frida_port")
                if (hookResult and 0x04 != 0) methods.add("frida_threads")
                if (hookResult and 0x08 != 0) methods.add("inline_hooks")

                eventEmitter.emit(
                    type = "hookingDetected",
                    severity = "critical",
                    metadata = mapOf(
                        "method" to methods.joinToString(","),
                        "bitmask" to hookResult,
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Hook detection error: ${e.message}")
        }
    }

    // ─── Slow checks ───

    /**
     * Multi-signal root detection (Kotlin + native).
     *
     * Combines 7 Kotlin signals with 2 native signals:
     * Kotlin: su paths, Magisk, SuperSU, KernelSU, build tags, SELinux, packages
     * Native: su binary access(), Magisk mount traces
     */
    private fun checkRoot() {
        try {
            val result = rootDetector?.detect(bridge) ?: return
            if (result.isRooted && !rootDetected.getAndSet(true)) {
                eventEmitter.emit(
                    type = "rootDetected",
                    severity = "critical",
                    metadata = mapOf(
                        "method" to result.detectionMethods,
                        "signals" to result.signalCount,
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Root detection error: ${e.message}")
        }
    }

    /**
     * Emulator/VM detection via scoring system.
     *
     * Checks build properties, hardware identifiers, emulator-specific
     * files, sensor count, and telephony. Requires score >= 3 to declare
     * emulator (avoids false positives on cheap devices).
     */
    private fun checkEmulator() {
        try {
            val result = emulatorDetector?.detect() ?: return
            if (result.isEmulator && !emulatorDetected.getAndSet(true)) {
                eventEmitter.emit(
                    type = "emulatorDetected",
                    severity = "high",
                    metadata = mapOf(
                        "method" to result.detectionMethods,
                        "score" to result.totalScore,
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Emulator detection error: ${e.message}")
        }
    }

    /**
     * APK and memory integrity verification.
     *
     * Checks DEX hash, loaded library count, and /proc/self/maps
     * for injection signatures.
     */
    private fun checkIntegrity() {
        try {
            val result = memoryProtection?.verifyAll() ?: return
            if (!result.isIntact && !integrityViolated.getAndSet(true)) {
                eventEmitter.emit(
                    type = "integrityViolation",
                    severity = "critical",
                    metadata = mapOf(
                        "failedChecks" to result.failedChecks,
                    )
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Integrity check error: ${e.message}")
        }
    }
}
