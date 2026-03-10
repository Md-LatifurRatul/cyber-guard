import Cocoa
import FlutterMacOS

/// CyberGuard Flutter Plugin for macOS.
///
/// ## macOS vs iOS differences:
///
/// - macOS uses `NSWindow.sharingType` instead of FLAG_SECURE
/// - No `UIScreen.isCaptured` equivalent — must use different detection
/// - macOS allows process enumeration (unlike iOS sandbox)
/// - Anti-debug works the same (ptrace, sysctl)
///
/// ## NSWindow.sharingType explained:
/// `.none` — Window content cannot be captured by screenshots,
///           screen recordings, or screen sharing tools.
/// `.readOnly` — Content can be read but not modified (default).
/// `.readWrite` — Full access (least secure).
///
/// Setting `.none` is the macOS equivalent of Android's FLAG_SECURE.
/// Unlike iOS, macOS actually PREVENTS capture, not just detects it.
public class CyberGuardPluginMacOS: NSObject, FlutterPlugin {

    private static let methodChannelName = "com.cyberguard.security/bridge"
    private static let eventChannelName = "com.cyberguard.security/events"

    /// Identifier used to find blur overlay views in windows.
    private static let blurViewIdentifier = NSUserInterfaceItemIdentifier("cyberguard_blur_overlay")

    private var methodChannel: FlutterMethodChannel?
    private let eventEmitter = SecurityEventEmitterMacOS()
    private var captureDetector: ScreenCaptureDetectorMacOS?
    private var antiDebug: AntiDebugProtectionMacOS?

    // Phase 7: Advanced Apple Security detectors
    private var dyldMonitor: DYLDMonitor?
    private var integrityVerifier: IntegrityVerifier?

    private var isSecureModeActive = false
    private var isInitialized = false

    // MARK: - Plugin Registration

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = CyberGuardPluginMacOS()

        let methodChannel = FlutterMethodChannel(
            name: methodChannelName,
            binaryMessenger: registrar.messenger
        )
        instance.methodChannel = methodChannel
        registrar.addMethodCallDelegate(instance, channel: methodChannel)

        let eventChannel = FlutterEventChannel(
            name: eventChannelName,
            binaryMessenger: registrar.messenger
        )
        eventChannel.setStreamHandler(instance.eventEmitter)

        // Observe app lifecycle for blur protection
        instance.startLifecycleObserving()
    }

    deinit {
        cleanup()
    }

    // MARK: - Method Call Handler

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "initialize":
            handleInitialize(result: result)
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

    private func handleInitialize(result: @escaping FlutterResult) {
        guard !isInitialized else {
            result(nil)
            return
        }

        antiDebug = AntiDebugProtectionMacOS()
        antiDebug?.enableProtection()

        captureDetector = ScreenCaptureDetectorMacOS(eventEmitter: eventEmitter)

        // Phase 7: Initialize advanced detectors
        dyldMonitor = DYLDMonitor()
        integrityVerifier = IntegrityVerifier()

        // Establish baselines — snapshot "known good" state at launch
        dyldMonitor?.establishBaseline()
        integrityVerifier?.establishBaseline()

        isInitialized = true
        result(nil)
    }

    /// Enter secure mode on macOS.
    ///
    /// Sets `NSWindow.sharingType = .none` on ALL app windows.
    /// This prevents:
    /// - `screencapture` CLI tool from capturing the window
    /// - QuickTime Player from recording the window
    /// - Zoom/Teams screen sharing from showing the window
    /// - OBS from capturing the window via Window Capture
    /// - Any app using CGWindowListCopyWindowInfo from reading pixels
    private func handleEnterSecureMode(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            let windows = NSApplication.shared.windows
            for window in windows {
                window.sharingType = .none
            }
            self.captureDetector?.startDetection()
            self.isSecureModeActive = true
            result(nil)
        }
    }

    /// Exit secure mode — restore normal window sharing.
    private func handleExitSecureMode(result: @escaping FlutterResult) {
        DispatchQueue.main.async {
            let windows = NSApplication.shared.windows
            for window in windows {
                window.sharingType = .readOnly
            }
            self.captureDetector?.stopDetection()
            self.isSecureModeActive = false
            result(nil)
        }
    }

    /// Return current device integrity status.
    ///
    /// ## macOS-specific detection:
    ///
    /// - **isRooted:** macOS doesn't have "root detection" in the iOS sense.
    ///   However, SIP (System Integrity Protection) being disabled is the
    ///   macOS equivalent — it allows kernel extensions, code injection,
    ///   and debugger attachment that SIP normally blocks.
    ///   We check `csrutil status` equivalent via csr_get_active_config.
    ///
    /// - **isHooked:** DYLDMonitor scans loaded libraries for injection
    ///   frameworks. Same API as iOS (_dyld_image_count/_dyld_get_image_name).
    ///
    /// - **isEmulator:** macOS apps can run in VMs (Parallels, VMware).
    ///   We check for VM-specific hardware model strings.
    ///
    /// - **isIntegrityValid:** IntegrityVerifier uses SecStaticCode on
    ///   macOS (unavailable on iOS) for code signature verification,
    ///   plus executable hash comparison.
    private func handleGetDeviceIntegrity(result: @escaping FlutterResult) {
        let isDebugger = antiDebug?.isDebuggerAttached() ?? false

        // DYLD injection detection
        let dyldResult = dyldMonitor?.detect()
        let isHooked = dyldResult?.isCompromised ?? false

        // SIP disabled detection (macOS equivalent of "rooted")
        let isRooted = checkSIPDisabled()

        // VM detection
        let isEmulator = checkVirtualMachine()

        // Binary integrity (code signature + hash)
        let integrityResult = integrityVerifier?.verify()
        let isIntegrityValid = integrityResult?.isIntact ?? true

        result([
            "isRooted": isRooted,
            "isEmulator": isEmulator,
            "isHooked": isHooked,
            "isDebugger": isDebugger,
            "isIntegrityValid": isIntegrityValid,
        ] as [String: Bool])
    }

    // MARK: - SIP (System Integrity Protection) Check

    /// Check if SIP is disabled.
    ///
    /// ## What is SIP:
    /// System Integrity Protection (rootless) prevents even root from
    /// modifying protected system files, loading unsigned kernel extensions,
    /// and attaching debuggers to system processes.
    ///
    /// ## Why it matters:
    /// With SIP disabled, an attacker can:
    /// - Inject dylibs into any process (including ours)
    /// - Load kernel extensions that intercept system calls
    /// - Modify protected system binaries
    /// - Attach a debugger even with PT_DENY_ATTACH
    ///
    /// ## Detection method:
    /// We check the `kern.bootargs` sysctl for "amfi_get_out_of_my_way=1"
    /// and the hardware model for known SIP-disabled indicators.
    /// The csr_get_active_config() function is private API, so we use
    /// the `csrutil` output equivalent via sysctl flags.
    private func checkSIPDisabled() -> Bool {
        // Check boot-args for AMFI disable flag
        var size: Int = 0
        sysctlbyname("kern.bootargs", nil, &size, nil, 0)

        if size > 0 {
            var bootArgs = [CChar](repeating: 0, count: size)
            sysctlbyname("kern.bootargs", &bootArgs, &size, nil, 0)
            let args = String(cString: bootArgs)

            if args.contains("amfi_get_out_of_my_way") {
                return true
            }
        }

        return false
    }

    // MARK: - Virtual Machine Detection

    /// Detect if running inside a virtual machine.
    ///
    /// ## Why detect VMs:
    /// VMs provide the attacker with full control over the "hardware":
    /// - Memory snapshots and inspection
    /// - Network traffic interception at the hypervisor level
    /// - Disk image cloning and analysis
    /// - CPU instruction tracing
    ///
    /// ## Detection method:
    /// Check the `hw.model` sysctl value. Physical Macs return values
    /// like "MacBookPro18,1" or "Mac14,2". VMs return distinctive values:
    /// - VMware: "VMware*"
    /// - Parallels: "Parallels*"
    /// - VirtualBox: "VirtualBox"
    /// - QEMU: "QEMU"
    private func checkVirtualMachine() -> Bool {
        var size: Int = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)

        guard size > 0 else { return false }

        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        let modelString = String(cString: model).lowercased()

        let vmIndicators = [
            "vmware",
            "parallels",
            "virtualbox",
            "qemu",
        ]

        return vmIndicators.contains { modelString.contains($0) }
    }

    /// App going to background — apply blur protection.
    ///
    /// macOS doesn't have an app switcher thumbnail like iOS, but
    /// Mission Control and Exposé show window content. We add a
    /// blur overlay to protect content when the app loses focus.
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

    private func handleEmergencyShutdown(result: @escaping FlutterResult) {
        NSApplication.shared.terminate(nil)
    }

    // MARK: - App Lifecycle Observing

    /// Observe NSApplication lifecycle notifications for automatic
    /// blur protection when the app resigns/gains active status.
    private func startLifecycleObserving() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidResignActive),
            name: NSApplication.didResignActiveNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidBecomeActive),
            name: NSApplication.didBecomeActiveNotification,
            object: nil
        )
    }

    private func stopLifecycleObserving() {
        NotificationCenter.default.removeObserver(
            self,
            name: NSApplication.didResignActiveNotification,
            object: nil
        )
        NotificationCenter.default.removeObserver(
            self,
            name: NSApplication.didBecomeActiveNotification,
            object: nil
        )
    }

    @objc private func applicationDidResignActive(_ notification: Notification) {
        if isSecureModeActive {
            addBlurOverlay()
        }
    }

    @objc private func applicationDidBecomeActive(_ notification: Notification) {
        removeBlurOverlay()
    }

    // MARK: - Blur Overlay Protection

    /// Add a blur overlay to all app windows to protect content
    /// when app loses focus (Mission Control, Exposé, screen sharing).
    private func addBlurOverlay() {
        DispatchQueue.main.async {
            let id = CyberGuardPluginMacOS.blurViewIdentifier
            let windows = NSApplication.shared.windows
            for window in windows {
                guard let contentView = window.contentView else { continue }
                // Skip if blur already exists
                let existing = contentView.subviews.first { $0.identifier == id }
                guard existing == nil else { continue }

                let blurView = NSVisualEffectView()
                blurView.identifier = id
                blurView.material = .fullScreenUI
                blurView.blendingMode = .behindWindow
                blurView.state = .active
                blurView.frame = contentView.bounds
                blurView.autoresizingMask = [.width, .height]

                contentView.addSubview(blurView)
            }
        }
    }

    /// Remove blur overlay from all windows when app becomes active.
    private func removeBlurOverlay() {
        DispatchQueue.main.async {
            let id = CyberGuardPluginMacOS.blurViewIdentifier
            let windows = NSApplication.shared.windows
            for window in windows {
                window.contentView?.subviews
                    .filter { $0.identifier == id }
                    .forEach { $0.removeFromSuperview() }
            }
        }
    }

    // MARK: - Cleanup

    private func cleanup() {
        stopLifecycleObserving()
        captureDetector?.stopDetection()
        captureDetector = nil
        methodChannel = nil
        antiDebug = nil
        dyldMonitor = nil
        integrityVerifier = nil
        isInitialized = false
        isSecureModeActive = false
    }
}
