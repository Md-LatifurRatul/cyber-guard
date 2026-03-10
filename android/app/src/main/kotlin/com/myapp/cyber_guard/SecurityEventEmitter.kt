package com.myapp.cyber_guard

import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.EventChannel

/**
 * Emits security events from Android native code to Flutter Dart.
 *
 * ## How EventChannel works:
 * 1. Dart calls `EventChannel.receiveBroadcastStream()` to start listening
 * 2. Flutter calls `onListen()` on this handler — we get an `EventSink`
 * 3. We call `eventSink.success(data)` to send events to Dart
 * 4. Dart receives the data in the stream listener
 * 5. When Dart cancels the stream, `onCancel()` is called
 *
 * ## Why a dedicated emitter:
 * - Separates event emission from plugin logic
 * - Thread-safe: all sink calls happen on the main thread via Handler
 * - Multiple producers (monitoring thread, callbacks) feed into one sink
 */
class SecurityEventEmitter : EventChannel.StreamHandler {

    private var eventSink: EventChannel.EventSink? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Called by Flutter when Dart starts listening to the EventChannel.
     * We store the sink reference for later use.
     */
    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    /**
     * Called by Flutter when Dart stops listening.
     * We clear the sink to prevent sending to a closed stream.
     */
    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    /**
     * Send a security event to Dart.
     *
     * Thread-safety: This can be called from ANY thread (monitoring thread,
     * MediaProjection callback, broadcast receiver). We post to the main
     * thread because EventSink.success() must be called on the UI thread.
     *
     * @param type The SecurityEventType name (must match Dart enum exactly)
     * @param severity One of: "low", "medium", "high", "critical"
     * @param metadata Optional additional data for forensic logging
     */
    fun emit(
        type: String,
        severity: String = "high",
        metadata: Map<String, Any> = emptyMap()
    ) {
        mainHandler.post {
            eventSink?.success(
                mapOf(
                    "type" to type,
                    "severity" to severity,
                    "timestamp" to System.currentTimeMillis(),
                    "metadata" to metadata
                )
            )
        }
    }

    /** Whether anyone is currently listening. */
    val isListening: Boolean get() = eventSink != null
}
