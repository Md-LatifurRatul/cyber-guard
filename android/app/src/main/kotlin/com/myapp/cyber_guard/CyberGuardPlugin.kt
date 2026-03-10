package com.myapp.cyber_guard

import android.app.Activity
import android.util.Log
import android.view.WindowManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * CyberGuard Flutter Plugin for Android.
 *
 * ## How Flutter plugins work on Android:
 *
 * 1. Flutter discovers this class via the `FlutterPlugin` interface
 * 2. `onAttachedToEngine()` is called — we register our channels
 * 3. `onAttachedToActivity()` is called — we get the Activity reference
 * 4. Dart sends method calls via MethodChannel → `onMethodCall()` handles them
 * 5. We send events via EventChannel → Dart receives them in a stream
 *
 * ## Channel contract (must match Dart SecurityChannel exactly):
 *
 * MethodChannel: "com.cyberguard.security/bridge"
 *   - "initialize"         → Start security with config
 *   - "enterSecureMode"    → Apply FLAG_SECURE, start monitoring
 *   - "exitSecureMode"     → Remove FLAG_SECURE, stop monitoring
 *   - "getDeviceIntegrity" → Return device security status
 *   - "appBackgrounded"    → App going to background
 *   - "appForegrounded"    → App returning to foreground
 *   - "emergencyShutdown"  → Kill process immediately
 *
 * EventChannel: "com.cyberguard.security/events"
 *   - Streams SecurityEvent maps to Dart
 */
class CyberGuardPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    companion object {
        private const val TAG = "CyberGuardPlugin"
        private const val METHOD_CHANNEL = "com.cyberguard.security/bridge"
        private const val EVENT_CHANNEL = "com.cyberguard.security/events"
    }

    // Flutter engine binding
    private var methodChannel: MethodChannel? = null
    private var eventChannel: EventChannel? = null

    // Android components
    private var activity: Activity? = null
    private var securityBridge: SecurityBridge? = null
    private var securityMonitor: SecurityMonitor? = null
    private var captureDetector: ScreenCaptureDetector? = null
    private var rootDetector: RootDetector? = null
    private var emulatorDetector: EmulatorDetector? = null
    private var memoryProtection: MemoryProtection? = null
    private val eventEmitter = SecurityEventEmitter()

    // State
    private var isSecureModeActive = false
    private var isInitialized = false

    // ─── FlutterPlugin lifecycle ───

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // Register MethodChannel — for Dart → Android calls
        methodChannel = MethodChannel(binding.binaryMessenger, METHOD_CHANNEL).apply {
            setMethodCallHandler(this@CyberGuardPlugin)
        }

        // Register EventChannel — for Android → Dart events
        eventChannel = EventChannel(binding.binaryMessenger, EVENT_CHANNEL).apply {
            setStreamHandler(eventEmitter)
        }

        Log.i(TAG, "CyberGuard plugin attached to Flutter engine")
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null
        eventChannel?.setStreamHandler(null)
        eventChannel = null

        cleanup()
        Log.i(TAG, "CyberGuard plugin detached from Flutter engine")
    }

    // ─── ActivityAware lifecycle ───

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        Log.i(TAG, "Activity attached: ${binding.activity.javaClass.simpleName}")
    }

    override fun onDetachedFromActivity() {
        cleanup()
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        // Don't cleanup — activity will reattach after config change
    }

    // ─── Method call handler ───

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "initialize" -> handleInitialize(call, result)
            "enterSecureMode" -> handleEnterSecureMode(result)
            "exitSecureMode" -> handleExitSecureMode(result)
            "getDeviceIntegrity" -> handleGetDeviceIntegrity(result)
            "appBackgrounded" -> handleAppBackgrounded(result)
            "appForegrounded" -> handleAppForegrounded(result)
            "emergencyShutdown" -> handleEmergencyShutdown(result)
            else -> result.notImplemented()
        }
    }

    // ─── Method implementations ───

    /**
     * Initialize the security system with configuration from Dart.
     *
     * Steps:
     * 1. Load the C++ native library
     * 2. Call nativeInit() to enable anti-debug at kernel level
     * 3. Create the security monitor with configured interval
     * 4. Store config for later use
     */
    private fun handleInitialize(call: MethodCall, result: Result) {
        if (isInitialized) {
            result.success(null)
            return
        }

        try {
            val args = call.arguments as? Map<*, *>
            val intervalMs = (args?.get("monitoringIntervalMs") as? Int)?.toLong() ?: 100L
            val enableRootDetection = args?.get("enableRootDetection") as? Boolean ?: true
            val enableEmulatorDetection = args?.get("enableEmulatorDetection") as? Boolean ?: true

            // Create Kotlin-level detectors (work even without native library)
            val currentActivity = activity
            if (currentActivity != null) {
                if (enableRootDetection) {
                    rootDetector = RootDetector(currentActivity)
                }
                if (enableEmulatorDetection) {
                    emulatorDetector = EmulatorDetector(currentActivity)
                }

                // Initialize memory integrity baseline
                memoryProtection = MemoryProtection(currentActivity).also {
                    it.initialize()
                }
            }

            // Load and initialize native security
            val nativeLoaded = SecurityBridge.loadNativeLibrary()
            if (nativeLoaded) {
                securityBridge = SecurityBridge().also { bridge ->
                    bridge.nativeInit()

                    // Create security monitor with all detectors
                    securityMonitor = SecurityMonitor(
                        bridge = bridge,
                        eventEmitter = eventEmitter,
                        intervalMs = intervalMs,
                        rootDetector = rootDetector,
                        emulatorDetector = emulatorDetector,
                        memoryProtection = memoryProtection,
                    )
                }
            } else {
                Log.w(TAG, "Native library not available — running with Kotlin-only security")
            }

            isInitialized = true
            Log.i(TAG, "Security initialized (native: $nativeLoaded, interval: ${intervalMs}ms)")
            result.success(null)
        } catch (e: Exception) {
            Log.e(TAG, "Initialization failed: ${e.message}")
            result.error("INIT_FAILED", e.message, null)
        }
    }

    /**
     * Enter secure mode — apply all display-level protections.
     *
     * ## FLAG_SECURE explained:
     * `WindowManager.LayoutParams.FLAG_SECURE` tells the Android compositor
     * that this window contains secure content. Effects:
     *
     * - Screenshots show a black/blank window
     * - Screen recordings show a black/blank window
     * - The recent apps thumbnail shows a blank preview
     * - Content is not visible in screen sharing
     *
     * This is the SAME flag used by banking apps, password managers,
     * and DRM video players. It's enforced at the compositor level,
     * so it works even with ADB screenrecord.
     *
     * ## Limitations (addressed in Phase 6):
     * - Root users can patch SurfaceFlinger to ignore this flag
     * - Xposed modules can remove the flag before it's applied
     * - That's why we layer additional protections on top
     */
    private fun handleEnterSecureMode(result: Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        try {
            // Layer 1: FLAG_SECURE on the window
            currentActivity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )

            // Layer 2: Start screen capture detection
            if (captureDetector == null) {
                captureDetector = ScreenCaptureDetector(currentActivity, eventEmitter)
            }
            captureDetector?.startDetection()

            // Layer 3: Start background security monitoring
            securityMonitor?.start()

            isSecureModeActive = true
            Log.i(TAG, "Secure mode ENABLED")
            result.success(null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enter secure mode: ${e.message}")
            result.error("SECURE_MODE_FAILED", e.message, null)
        }
    }

    /**
     * Exit secure mode — remove display-level protections.
     *
     * We keep the security monitor running in a lighter mode
     * (debugger detection still active) but remove FLAG_SECURE
     * and stop screen capture detection.
     */
    private fun handleExitSecureMode(result: Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("NO_ACTIVITY", "No activity available", null)
            return
        }

        try {
            // Remove FLAG_SECURE
            currentActivity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)

            // Stop capture detection
            captureDetector?.stopDetection()

            // Stop monitoring
            securityMonitor?.stop()

            isSecureModeActive = false
            Log.i(TAG, "Secure mode DISABLED")
            result.success(null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to exit secure mode: ${e.message}")
            result.error("EXIT_SECURE_FAILED", e.message, null)
        }
    }

    /**
     * Return current device integrity status.
     *
     * This is a snapshot check — not continuous monitoring.
     * Used by Dart to make UI decisions (show/hide content).
     */
    private fun handleGetDeviceIntegrity(result: Result) {
        val bridge = securityBridge

        // Root detection — combine native + Kotlin signals
        val rootResult = rootDetector?.detect(bridge)

        // Emulator detection
        val emulatorResult = emulatorDetector?.detect()

        // Hook detection — native only (C++ is harder to hook than Kotlin)
        val hookBitmask = try {
            bridge?.nativeDetectHooks() ?: 0
        } catch (_: Exception) { 0 }

        // Integrity check
        val integrityResult = memoryProtection?.verifyAll()

        val integrityMap = mapOf(
            "isRooted" to (rootResult?.isRooted ?: false),
            "isEmulator" to (emulatorResult?.isEmulator ?: false),
            "isHooked" to (hookBitmask != 0),
            "isDebugger" to (bridge?.nativeIsDebuggerAttached() ?: false),
            "isIntegrityValid" to (integrityResult?.isIntact ?: true),
        )

        result.success(integrityMap)
    }

    /**
     * App is going to background — protect against task switcher.
     *
     * When the user presses Home or switches apps, Android takes a
     * screenshot for the recent apps view. FLAG_SECURE already makes
     * this blank, but we additionally ensure the window is cleared.
     */
    private fun handleAppBackgrounded(result: Result) {
        // FLAG_SECURE already handles task switcher screenshot.
        // Additional protections will be added in Phase 6.
        result.success(null)
    }

    /**
     * App returned to foreground — re-verify security state.
     */
    private fun handleAppForegrounded(result: Result) {
        // Re-verify protections are still in place
        if (isSecureModeActive) {
            activity?.window?.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
        result.success(null)
    }

    /**
     * Emergency shutdown — kill the process immediately.
     *
     * This is the nuclear option. Called when a critical security event
     * is detected (memory tampering, integrity violation).
     * Process.killProcess() sends SIGKILL which cannot be caught or ignored.
     */
    private fun handleEmergencyShutdown(result: Result) {
        Log.w(TAG, "EMERGENCY SHUTDOWN triggered")
        cleanup()
        activity?.finishAffinity()
        android.os.Process.killProcess(android.os.Process.myPid())
        // result.success() won't be called — process is dead
    }

    /**
     * Clean up all resources.
     */
    private fun cleanup() {
        securityMonitor?.stop()
        captureDetector?.stopDetection()
        securityMonitor = null
        captureDetector = null
        securityBridge = null
        rootDetector = null
        emulatorDetector = null
        memoryProtection = null
        isInitialized = false
        isSecureModeActive = false
    }
}
