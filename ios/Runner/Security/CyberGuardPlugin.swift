import Flutter
import UIKit

/// CyberGuard Flutter Plugin for iOS.
///
/// ## How Flutter plugins work on iOS:
///
/// 1. `AppDelegate` calls `register(with:)` to connect this plugin to Flutter
/// 2. We get a `FlutterPluginRegistrar` which provides access to the binary messenger
/// 3. We create MethodChannel + EventChannel on that messenger
/// 4. Dart sends method calls → `handle(_:result:)` processes them
/// 5. We send events via `SecurityEventEmitter` → Dart receives them in a stream
///
/// ## Channel contract (must match Dart SecurityChannel exactly):
///
/// MethodChannel: "com.cyberguard.security/bridge"
///   - "initialize"         → Start security with config
///   - "enterSecureMode"    → Enable capture detection, anti-debug
///   - "exitSecureMode"     → Disable capture detection
///   - "getDeviceIntegrity" → Return device security status
///   - "appBackgrounded"    → App entering background
///   - "appForegrounded"    → App returning to foreground
///   - "emergencyShutdown"  → Terminate process immediately
///
/// EventChannel: "com.cyberguard.security/events"
///   - Streams SecurityEvent dictionaries to Dart
public class CyberGuardPlugin: NSObject, FlutterPlugin {

    // MARK: - Channel Names (must match Dart side exactly)

    private static let methodChannelName = "com.cyberguard.security/bridge"
    private static let eventChannelName = "com.cyberguard.security/events"

    // MARK: - Components

    private var methodChannel: FlutterMethodChannel?
    private let eventEmitter = SecurityEventEmitter()
    private var captureDetector: ScreenCaptureDetector?
    private var antiDebug: AntiDebugProtection?

    // Phase 7: Advanced Apple Security detectors
    private var jailbreakDetector: JailbreakDetector?
    private var dyldMonitor: DYLDMonitor?
    private var integrityVerifier: IntegrityVerifier?

    // MARK: - State

    private var isSecureModeActive = false
    private var isInitialized = false

    // MARK: - Plugin Registration

    /// Called by Flutter to register this plugin.
    /// This is the iOS equivalent of Android's `onAttachedToEngine`.
    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = CyberGuardPlugin()

        // MethodChannel: Dart → iOS calls
        let methodChannel = FlutterMethodChannel(
            name: methodChannelName,
            binaryMessenger: registrar.messenger()
        )
        instance.methodChannel = methodChannel
        registrar.addMethodCallDelegate(instance, channel: methodChannel)

        // EventChannel: iOS → Dart events
        let eventChannel = FlutterEventChannel(
            name: eventChannelName,
            binaryMessenger: registrar.messenger()
        )
        eventChannel.setStreamHandler(instance.eventEmitter)

        // Listen for app lifecycle
        registrar.addApplicationDelegate(instance)
    }

    // MARK: - Method Call Handler

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "initialize":
            handleInitialize(call: call, result: result)
        case "enterSecureMode":
            handleEnterSecureMode(result: result)
        case "exitSecureMode":
            handleExitSecureMode(result: result)
        case "getDeviceIntegrity":
            handleGetDeviceIntegrity(result: result)
        case "appBackgrounded":
            handleAppBackgrounded(result: result)
        case "appForegrounded":
            handleAppForegrounded(result: result)
        case "emergencyShutdown":
            handleEmergencyShutdown(result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Method Implementations

    /// Initialize the security system with configuration from Dart.
    ///
    /// Steps:
    /// 1. Parse config from Dart arguments
    /// 2. Enable anti-debugging (PT_DENY_ATTACH)
    /// 3. Create screen capture detector
    /// 4. Store config for later use
    private func handleInitialize(call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard !isInitialized else {
            result(nil)
            return
        }

        // Enable anti-debugging before anything else
        antiDebug = AntiDebugProtection()
        antiDebug?.enableProtection()

        // Create screen capture detector
        captureDetector = ScreenCaptureDetector(eventEmitter: eventEmitter)

        // Phase 7: Initialize advanced detectors
        jailbreakDetector = JailbreakDetector()
        dyldMonitor = DYLDMonitor()
        integrityVerifier = IntegrityVerifier()

        // Establish baselines before entering secure mode.
        // Baseline = snapshot of "known good" state at launch.
        // Any deviation detected later indicates tampering.
        dyldMonitor?.establishBaseline()
        integrityVerifier?.establishBaseline()

        isInitialized = true
        result(nil)
    }

    /// Enter secure mode — activate all iOS protection layers.
    ///
    /// ## iOS Protection Stack:
    ///
    /// ### Layer 1: UIScreen.isCaptured monitoring
    /// iOS provides a boolean property `UIScreen.main.isCaptured` that returns
    /// true when screen is being recorded, AirPlayed, or mirrored.
    /// We observe `capturedDidChangeNotification` for instant detection.
    /// Unlike Android's FLAG_SECURE, this doesn't automatically black out content —
    /// we must blur/hide it ourselves in response to the notification.
    ///
    /// ### Layer 2: Screenshot notification
    /// `UIApplication.userDidTakeScreenshotNotification` fires AFTER a screenshot
    /// is taken. We can't prevent it, but we can detect it for forensic logging
    /// and to trigger immediate content change.
    ///
    /// ### Layer 3: Anti-debug (PT_DENY_ATTACH)
    /// Prevents debuggers from attaching. Already enabled in initialize().
    private func handleEnterSecureMode(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            self.captureDetector?.startDetection()
            self.isSecureModeActive = true
            result(nil)
        }
    }

    /// Exit secure mode — stop capture detection.
    private func handleExitSecureMode(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            self.captureDetector?.stopDetection()
            self.isSecureModeActive = false
            result(nil)
        }
    }

    /// Return current device integrity status.
    ///
    /// ## Phase 7 detection flow:
    ///
    /// 1. **isRooted (jailbroken):** JailbreakDetector runs 7 signals
    ///    (files, URLs, sandbox, fork, dylibs, symlinks, env vars).
    ///    Any single positive = jailbroken.
    ///
    /// 2. **isHooked:** DYLDMonitor scans loaded images for known
    ///    injection frameworks (Frida, Substrate, Cycript, etc.)
    ///    and checks for unexpected library count growth.
    ///
    /// 3. **isEmulator:** On iOS, we check for simulator-specific
    ///    indicators. Real devices run ARM; simulator runs x86_64/arm64
    ///    on the Mac with different environment characteristics.
    ///
    /// 4. **isIntegrityValid:** IntegrityVerifier checks executable
    ///    hash against baseline and FairPlay encryption status.
    private func handleGetDeviceIntegrity(result: @escaping FlutterResult) {
        let isDebugger = antiDebug?.isDebuggerAttached() ?? false

        // Jailbreak detection (7 signals)
        let jailbreakResult = jailbreakDetector?.detect()
        let isRooted = jailbreakResult?.isJailbroken ?? false

        // DYLD injection detection
        let dyldResult = dyldMonitor?.detect()
        let isHooked = dyldResult?.isCompromised ?? false

        // Simulator detection
        let isEmulator = checkSimulatorEnvironment()

        // Binary integrity
        let integrityResult = integrityVerifier?.verify()
        let isIntegrityValid = integrityResult?.isIntact ?? true

        let integrityMap: [String: Bool] = [
            "isRooted": isRooted,
            "isEmulator": isEmulator,
            "isHooked": isHooked,
            "isDebugger": isDebugger,
            "isIntegrityValid": isIntegrityValid,
        ]

        result(integrityMap)
    }

    // MARK: - Simulator Detection

    /// Detect if running in iOS Simulator.
    ///
    /// ## How simulator detection works:
    ///
    /// The iOS Simulator is NOT an emulator — it runs native code on the
    /// Mac's CPU. But it has distinct characteristics:
    ///
    /// - **TARGET_OS_SIMULATOR:** Compile-time flag set by Xcode when
    ///   building for the simulator. This is the most reliable check.
    ///
    /// - **ProcessInfo model:** Simulator reports "iPhone" or "iPad"
    ///   but the underlying hardware is actually "x86_64" or "arm64"
    ///   Mac hardware. We check the `SIMULATOR_DEVICE_NAME` env var.
    ///
    /// ## Why detect simulators:
    /// Simulators are used by attackers to run the app in a controlled
    /// environment where they can inspect memory, intercept network
    /// traffic, and bypass hardware-backed security (Secure Enclave).
    private func checkSimulatorEnvironment() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        // Runtime fallback: check for simulator env vars
        // These are set by Xcode when launching in the simulator
        if ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil {
            return true
        }
        return false
        #endif
    }

    /// App going to background — apply blur protection.
    ///
    /// iOS takes a snapshot when app enters background for the app switcher.
    /// Unlike Android's FLAG_SECURE, iOS doesn't have a built-in secure flag.
    /// We add a blur overlay view to the window before the snapshot is taken.
    private func handleAppBackgrounded(result: @escaping FlutterResult) {
        if isSecureModeActive {
            addBlurOverlay()
        }
        result(nil)
    }

    /// App returning to foreground — remove blur overlay.
    private func handleAppForegrounded(result: @escaping FlutterResult) {
        removeBlurOverlay()
        result(nil)
    }

    /// Emergency shutdown — terminate immediately.
    private func handleEmergencyShutdown(result: @escaping FlutterResult) {
        cleanup()
        exit(1)
    }

    // MARK: - App Switcher Blur Protection

    private static let blurViewTag = 99887

    /// Add a blur overlay to prevent app switcher screenshot leaking content.
    ///
    /// How this works:
    /// When iOS captures the app switcher thumbnail, it captures the current
    /// window state. By adding a full-screen blur view on top of everything,
    /// the thumbnail shows only blur — no content visible.
    private func addBlurOverlay() {
        DispatchQueue.main.async {
            guard let window = self.getKeyWindow() else { return }
            // Don't add duplicate blur views
            guard window.viewWithTag(CyberGuardPlugin.blurViewTag) == nil else { return }

            let blurEffect = UIBlurEffect(style: .dark)
            let blurView = UIVisualEffectView(effect: blurEffect)
            blurView.frame = window.bounds
            blurView.tag = CyberGuardPlugin.blurViewTag
            blurView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            window.addSubview(blurView)
        }
    }

    /// Remove the blur overlay when returning to foreground.
    private func removeBlurOverlay() {
        DispatchQueue.main.async {
            guard let window = self.getKeyWindow() else { return }
            window.viewWithTag(CyberGuardPlugin.blurViewTag)?.removeFromSuperview()
        }
    }

    /// Get the key window in a way that works across iOS versions.
    private func getKeyWindow() -> UIWindow? {
        if #available(iOS 15.0, *) {
            return UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap { $0.windows }
                .first { $0.isKeyWindow }
        } else {
            return UIApplication.shared.windows.first { $0.isKeyWindow }
        }
    }

    // MARK: - Cleanup

    private func cleanup() {
        captureDetector?.stopDetection()
        captureDetector = nil
        antiDebug = nil
        jailbreakDetector = nil
        dyldMonitor = nil
        integrityVerifier = nil
        isInitialized = false
        isSecureModeActive = false
    }
}

// MARK: - App Lifecycle (FlutterApplicationLifeCycleDelegate)

extension CyberGuardPlugin {
    /// Called when app is about to resign active state (entering background).
    public func applicationWillResignActive(_ application: UIApplication) {
        if isSecureModeActive {
            addBlurOverlay()
        }
    }

    /// Called when app becomes active (returning to foreground).
    public func applicationDidBecomeActive(_ application: UIApplication) {
        removeBlurOverlay()
    }
}
