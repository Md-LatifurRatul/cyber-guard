package com.myapp.cyber_guard

import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Display
import io.flutter.plugin.common.MethodChannel

/**
 * Detects screen capture, screen recording, and screen mirroring on Android.
 *
 * ## Three independent detection methods:
 *
 * ### Method 1: Display state monitoring (API 17+)
 * Android's DisplayManager tracks all connected displays.
 * When screen mirroring or casting starts, a virtual display is created.
 * We listen for display additions and check their flags.
 *
 * ### Method 2: Screen capture callback (API 34+)
 * Android 14 introduced `Activity.registerScreenCaptureCallback()`.
 * This is the OFFICIAL API for detecting screenshots.
 * The OS calls our callback when a screenshot is taken.
 *
 * ### Method 3: Native process scanning (via C++ SecurityBridge)
 * Scans /proc for screenrecord, ffmpeg, obs, etc.
 * This catches recording tools that don't use MediaProjection.
 * Handled separately in SecurityMonitor.
 *
 * ## Why multiple methods:
 * - Each method catches different attack vectors
 * - Method 1 catches ADB screenrecord and mirroring
 * - Method 2 catches system screenshots (power + volume down)
 * - Method 3 catches third-party recording apps
 * - If one is bypassed, the others still protect
 */
class ScreenCaptureDetector(
    private val activity: Activity,
    private val eventEmitter: SecurityEventEmitter,
    private val methodChannel: MethodChannel? = null
) {
    companion object {
        private const val TAG = "CaptureDetector"
        /** Delay before auto-clearing screenshot capture state (ms). */
        private const val SCREENSHOT_CLEAR_DELAY_MS = 2000L
    }

    private var displayListener: DisplayManager.DisplayListener? = null
    private var screenCaptureCallback: Activity.ScreenCaptureCallback? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Start all available detection methods.
     * Call this in Activity.onCreate() or when entering secure mode.
     */
    fun startDetection() {
        startDisplayMonitoring()
        startScreenCaptureCallback()
        Log.i(TAG, "Screen capture detection started")
    }

    /**
     * Stop all detection methods.
     * Call this when leaving secure mode.
     */
    fun stopDetection() {
        stopDisplayMonitoring()
        stopScreenCaptureCallback()
        Log.i(TAG, "Screen capture detection stopped")
    }

    // ─── Method 1: Display Monitoring ───

    /**
     * Monitor for virtual displays (indicates mirroring/casting/recording).
     *
     * When a user starts screen recording via the system or a 3rd-party app,
     * Android creates a virtual display with FLAG_PRESENTATION.
     * We detect this and fire a security event.
     */
    private fun startDisplayMonitoring() {
        val displayManager = activity.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager

        displayListener = object : DisplayManager.DisplayListener {
            override fun onDisplayAdded(displayId: Int) {
                val display = displayManager.getDisplay(displayId) ?: return
                checkDisplaySecurity(display)
            }

            override fun onDisplayChanged(displayId: Int) {
                val display = displayManager.getDisplay(displayId) ?: return
                checkDisplaySecurity(display)
            }

            override fun onDisplayRemoved(displayId: Int) {
                // Virtual display removed — recording/mirroring stopped.
                // Clear the capture state so content blur deactivates.
                Log.i(TAG, "Virtual display removed (ID: $displayId), clearing capture state")
                emitCaptureCleared()
            }
        }

        displayManager.registerDisplayListener(displayListener, mainHandler)

        // Also check existing displays at startup
        for (display in displayManager.displays) {
            checkDisplaySecurity(display)
        }
    }

    private fun stopDisplayMonitoring() {
        displayListener?.let { listener ->
            val displayManager = activity.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
            displayManager.unregisterDisplayListener(listener)
        }
        displayListener = null
    }

    /**
     * Check if a display indicates screen capture.
     *
     * Display flags we check:
     * - FLAG_PRESENTATION: This is a presentation display (Chromecast, etc.)
     * - FLAG_PRIVATE: Cannot be accessed by other apps (safe)
     * - FLAG_SECURE: Protected content display (safe)
     *
     * A virtual display WITHOUT FLAG_SECURE or FLAG_PRIVATE that
     * ISN'T the default display = likely screen recording.
     */
    private fun checkDisplaySecurity(display: Display) {
        // Default display (physical screen) is always ID 0
        if (display.displayId == Display.DEFAULT_DISPLAY) return

        val flags = display.flags
        val isSecure = (flags and Display.FLAG_SECURE) != 0
        val isPrivate = (flags and Display.FLAG_PRIVATE) != 0

        // If the virtual display is neither secure nor private,
        // it can capture our content
        if (!isSecure && !isPrivate) {
            Log.w(TAG, "Insecure virtual display detected: ${display.name} (ID: ${display.displayId})")
            eventEmitter.emit(
                type = "screenCapture",
                severity = "high",
                metadata = mapOf(
                    "method" to "display_monitoring",
                    "displayName" to (display.name ?: "unknown"),
                    "displayId" to display.displayId
                )
            )
        }
    }

    // ─── Method 2: Screen Capture Callback (Android 14+) ───

    /**
     * Register the official Android 14 screenshot detection callback.
     *
     * This is the most reliable method on Android 14+ because it's
     * a direct OS notification — no polling, no race conditions.
     * The OS guarantees the callback fires when a screenshot is taken.
     */
    private fun startScreenCaptureCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                val callback = Activity.ScreenCaptureCallback {
                    Log.w(TAG, "Screenshot detected via Android 14 callback")
                    eventEmitter.emit(
                        type = "screenCapture",
                        severity = "high",
                        metadata = mapOf("method" to "screen_capture_callback")
                    )
                    // Screenshots are instantaneous — auto-clear after brief delay
                    // so the blur deactivates and content becomes visible again
                    mainHandler.postDelayed({ emitCaptureCleared() }, SCREENSHOT_CLEAR_DELAY_MS)
                }
                screenCaptureCallback = callback
                activity.registerScreenCaptureCallback(activity.mainExecutor, callback)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register screen capture callback: ${e.message}")
            }
        }
    }

    /**
     * Unregister the Android 14 screenshot callback to prevent memory leaks.
     */
    private fun stopScreenCaptureCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            screenCaptureCallback?.let { callback ->
                try {
                    activity.unregisterScreenCaptureCallback(callback)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to unregister screen capture callback: ${e.message}")
                }
            }
            screenCaptureCallback = null
        }
    }

    // ─── Capture Cleared ───

    /**
     * Notify Dart that screen capture has stopped.
     *
     * Calls Dart's `onCaptureCleared` method via the MethodChannel,
     * which clears `isScreenBeingCaptured` and deactivates the blur shield.
     */
    private fun emitCaptureCleared() {
        mainHandler.post {
            try {
                methodChannel?.invokeMethod("onCaptureCleared", null)
                Log.i(TAG, "Capture cleared event sent to Dart")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send capture cleared: ${e.message}")
            }
        }
    }
}
