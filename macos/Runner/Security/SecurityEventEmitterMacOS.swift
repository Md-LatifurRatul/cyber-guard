import FlutterMacOS
import Foundation

/// macOS event emitter — identical logic to iOS version.
/// Separate class because macOS uses `FlutterMacOS` framework.
class SecurityEventEmitterMacOS: NSObject, FlutterStreamHandler {

    private var eventSink: FlutterEventSink?
    var isListening: Bool { eventSink != nil }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        self.eventSink = events
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        self.eventSink = nil
        return nil
    }

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
