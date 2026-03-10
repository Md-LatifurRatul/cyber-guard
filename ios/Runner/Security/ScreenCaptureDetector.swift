import UIKit

/// Detects screen capture, recording, and mirroring on iOS.
///
/// ## Three independent detection methods:
///
/// ### Method 1: UIScreen.isCaptured (iOS 11+)
/// Apple's official API. Returns `true` when:
///   - Screen recording is active (Control Center recorder)
///   - AirPlay mirroring is active
///   - Third-party screen recording app is capturing
///
/// We observe `capturedDidChangeNotification` for real-time detection.
/// This is extremely reliable — Apple controls the entire display pipeline.
///
/// ### Method 2: Screenshot notification (iOS 7+)
/// `userDidTakeScreenshotNotification` fires AFTER a screenshot is taken.
/// We CANNOT prevent the screenshot, but we can:
///   - Log it for forensics (who, when, what was on screen)
///   - Immediately blur content to prevent repeat captures
///   - Notify the server for audit trail
///
/// ### Method 3: Darwin notification (system level)
/// The SpringBoard process posts `com.apple.springboard.screencapture`
/// when a screenshot is initiated. This fires slightly BEFORE the
/// screenshot is taken, giving us a tiny window to blur content.
///
/// ## Why we can't fully prevent screenshots on iOS:
/// Unlike Android's FLAG_SECURE, iOS has no API to prevent screenshots.
/// Apple's philosophy: the user owns the device, so screenshots are a
/// user right. Our defense-in-depth strategy is:
///   1. Detect captures instantly
///   2. Blur content as fast as possible
///   3. Embed invisible watermarks (Phase 4) so leaked content is traceable
///   4. Log everything for forensic investigation
class ScreenCaptureDetector {

    private let eventEmitter: SecurityEventEmitter
    private var isMonitoring = false

    init(eventEmitter: SecurityEventEmitter) {
        self.eventEmitter = eventEmitter
    }

    deinit {
        stopDetection()
    }

    // MARK: - Public API

    /// Start all detection methods.
    func startDetection() {
        guard !isMonitoring else { return }
        isMonitoring = true

        startCaptureMonitoring()
        startScreenshotMonitoring()
        startDarwinNotificationMonitoring()

        // Check initial state — screen might already be captured
        checkCurrentCaptureState()
    }

    /// Stop all detection methods.
    func stopDetection() {
        guard isMonitoring else { return }
        isMonitoring = false

        // Remove each observer explicitly for clarity and safety
        NotificationCenter.default.removeObserver(
            self,
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
        NotificationCenter.default.removeObserver(
            self,
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
        stopDarwinNotificationMonitoring()
    }

    // MARK: - Method 1: UIScreen.isCaptured

    /// Monitor UIScreen.isCaptured via NotificationCenter.
    ///
    /// `capturedDidChangeNotification` fires whenever the capture state
    /// changes — both when recording STARTS and when it STOPS.
    /// This lets us blur on start and unblur on stop.
    private func startCaptureMonitoring() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(screenCaptureStateChanged),
            name: UIScreen.capturedDidChangeNotification,
            object: nil
        )
    }

    @objc private func screenCaptureStateChanged(_ notification: Notification) {
        let isCaptured = UIScreen.main.isCaptured

        if isCaptured {
            eventEmitter.emit(
                type: "screenCapture",
                severity: "high",
                metadata: ["method": "ui_screen_captured"]
            )
        }
        // When isCaptured becomes false (recording stopped), Dart side
        // will receive "onCaptureCleared" via MethodChannel from the plugin.
    }

    /// Check if screen is currently being captured at startup.
    private func checkCurrentCaptureState() {
        if UIScreen.main.isCaptured {
            eventEmitter.emit(
                type: "screenCapture",
                severity: "high",
                metadata: ["method": "ui_screen_captured_initial"]
            )
        }
    }

    // MARK: - Method 2: Screenshot Notification

    /// Monitor for screenshots taken by the user.
    ///
    /// This notification fires AFTER the screenshot is captured.
    /// We use it primarily for audit logging — the content has already
    /// been captured, but we record WHO took it and WHEN.
    private func startScreenshotMonitoring() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(screenshotTaken),
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil
        )
    }

    @objc private func screenshotTaken(_ notification: Notification) {
        eventEmitter.emit(
            type: "screenCapture",
            severity: "medium",
            metadata: ["method": "screenshot_notification"]
        )
    }

    // MARK: - Method 3: Darwin Notification

    /// Monitor system-level Darwin notifications for screen capture.
    ///
    /// Darwin notifications are lower-level than NSNotificationCenter.
    /// They come from the kernel/SpringBoard and can detect captures
    /// that the higher-level APIs might miss.
    ///
    /// `com.apple.springboard.screencapture` is posted by SpringBoard
    /// when the user initiates a screenshot (before it's fully captured).
    ///
    /// ## Safety:
    /// We pass `self` as an unretained pointer to CFNotificationCenter.
    /// `stopDarwinNotificationMonitoring()` MUST be called before this
    /// object is deallocated (enforced via `deinit`). The callback also
    /// guards against nil and checks `isMonitoring` before accessing state.
    private func startDarwinNotificationMonitoring() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()

        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            darwinNotificationCallback,
            "com.apple.springboard.screencapture" as CFString,
            nil,
            .deliverImmediately
        )
    }

    private func stopDarwinNotificationMonitoring() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveEveryObserver(center, Unmanaged.passUnretained(self).toOpaque())
    }

    /// Handle Darwin notification — called from C callback.
    fileprivate func handleDarwinScreenCapture() {
        guard isMonitoring else { return }
        eventEmitter.emit(
            type: "screenCapture",
            severity: "high",
            metadata: ["method": "darwin_notification"]
        )
    }
}

// MARK: - Darwin Notification C Callback

/// Static C function callback required by CFNotificationCenter.
///
/// CFNotificationCenter predates Swift and requires a C function pointer.
/// We pass `self` as the observer opaque pointer, then recover it here
/// to call back into Swift. The `isMonitoring` guard inside
/// `handleDarwinScreenCapture` provides a safety check.
private func darwinNotificationCallback(
    center: CFNotificationCenter?,
    observer: UnsafeMutableRawPointer?,
    name: CFNotificationName?,
    object: UnsafeRawPointer?,
    userInfo: CFDictionary?
) {
    guard let observer = observer else { return }
    let detector = Unmanaged<ScreenCaptureDetector>.fromOpaque(observer).takeUnretainedValue()
    detector.handleDarwinScreenCapture()
}
