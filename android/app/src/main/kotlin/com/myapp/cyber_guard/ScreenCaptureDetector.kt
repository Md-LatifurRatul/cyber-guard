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
    private val eventEmitter: SecurityEventEmitter
) {
    companion object {
        private const val TAG = "CaptureDetector"
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
                // Display removed — mirroring/recording may have stopped.
                // We don't clear the event here because the recording
                // might have already captured content.
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
}
