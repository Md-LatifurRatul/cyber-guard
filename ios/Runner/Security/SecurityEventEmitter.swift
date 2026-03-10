import Flutter
import Foundation

/// Emits security events from iOS native code to Flutter Dart.
///
/// ## How FlutterEventChannel works on iOS:
///
/// 1. Dart calls `EventChannel.receiveBroadcastStream()` to start listening
/// 2. Flutter calls `onListen()` on this handler — we get a `FlutterEventSink`
/// 3. We call `eventSink(data)` to send events to Dart
/// 4. When Dart cancels, `onCancel()` is called
///
/// ## Thread Safety:
/// `FlutterEventSink` must be called on the main thread.
/// All emit() calls dispatch to DispatchQueue.main.
class SecurityEventEmitter: NSObject, FlutterStreamHandler {

    /// The sink provided by Flutter when Dart starts listening.
    private var eventSink: FlutterEventSink?

    /// Whether anyone is currently listening.
    var isListening: Bool { eventSink != nil }

    // MARK: - FlutterStreamHandler

    /// Called when Dart starts listening to the EventChannel.
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        self.eventSink = events
        return nil
    }

    /// Called when Dart stops listening.
    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        self.eventSink = nil
        return nil
    }

    // MARK: - Event Emission

    /// Send a security event to Dart.
    ///
    /// Dispatches to main thread because FlutterEventSink must be called
    /// from the platform thread (main/UI thread on iOS).
    ///
    /// - Parameters:
    ///   - type: SecurityEventType name (must match Dart enum: "screenCapture", "debuggerAttached", etc.)
    ///   - severity: One of "low", "medium", "high", "critical"
    ///   - metadata: Optional additional data for forensic logging
    func emit(type: String, severity: String = "high", metadata: [String: Any] = [:]) {
        guard isListening else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let sink = self.eventSink else { return }
            sink([
                "type": type,
                "severity": severity,
                "timestamp": Int(Date().timeIntervalSince1970 * 1000),
                "metadata": metadata
            ])
        }
    }
}
