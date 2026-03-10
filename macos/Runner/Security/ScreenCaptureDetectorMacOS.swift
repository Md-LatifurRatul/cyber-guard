import Cocoa
import FlutterMacOS

/// Detects screen capture attempts on macOS for audit logging.
///
/// ## macOS vs iOS capture detection:
///
/// On macOS, `NSWindow.sharingType = .none` PREVENTS capture entirely.
/// But we still want to DETECT attempts for audit/forensic purposes.
///
/// ## Detection methods:
///
/// ### Method 1: Darwin notification for screencapture
/// The system `screencapture` tool (Cmd+Shift+3/4/5) posts Darwin
/// notifications that we can observe. This catches the built-in
/// screenshot tool.
///
/// ### Method 2: Process scanning (handled in Phase 6)
/// We can scan running processes for known recording tools
/// (OBS, QuickTime, etc.) since macOS doesn't sandbox process lists.
class ScreenCaptureDetectorMacOS {

    private let eventEmitter: SecurityEventEmitterMacOS
    private var isMonitoring = false

    init(eventEmitter: SecurityEventEmitterMacOS) {
        self.eventEmitter = eventEmitter
    }

    deinit {
        stopDetection()
    }

    // MARK: - Public API

    func startDetection() {
        guard !isMonitoring else { return }
        isMonitoring = true
        startDarwinNotificationMonitoring()
    }

    func stopDetection() {
        guard isMonitoring else { return }
        isMonitoring = false
        stopDarwinNotificationMonitoring()
    }

    // MARK: - Darwin Notification Monitoring

    /// Monitor Darwin notifications for macOS screenshot events.
    ///
    /// These notifications fire when the user takes a screenshot
    /// via Cmd+Shift+3/4/5 or the screencapture CLI tool.
    private func startDarwinNotificationMonitoring() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let name = "com.apple.screencapture.save" as CFString

        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            macOSDarwinNotificationCallback,
            name,
            nil,
            .deliverImmediately
        )
    }

    private func stopDarwinNotificationMonitoring() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveEveryObserver(center, Unmanaged.passUnretained(self).toOpaque())
    }

    /// Handle Darwin notification — called from C callback.
    fileprivate func handleScreenCaptureAttempt() {
        guard isMonitoring else { return }
        eventEmitter.emit(
            type: "screenCapture",
            severity: "medium",
            metadata: [
                "method": "darwin_notification_macos",
                "blocked": true
            ]
        )
    }
}

// MARK: - Darwin Notification C Callback

private func macOSDarwinNotificationCallback(
    center: CFNotificationCenter?,
    observer: UnsafeMutableRawPointer?,
    name: CFNotificationName?,
    object: UnsafeRawPointer?,
    userInfo: CFDictionary?
) {
    guard let observer = observer else { return }
    let detector = Unmanaged<ScreenCaptureDetectorMacOS>.fromOpaque(observer).takeUnretainedValue()
    detector.handleScreenCaptureAttempt()
}
