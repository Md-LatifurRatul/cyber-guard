/// Immutable configuration for the CyberGuard security framework.
///
/// Defines which protection layers are enabled and their parameters.
/// Pass this to [SecurityChannel.initialize] to configure the native side.
class SecurityConfig {
  const SecurityConfig({
    this.enableScreenCaptureProtection = true,
    this.enableAntiDebugging = true,
    this.enableRootDetection = true,
    this.enableEmulatorDetection = true,
    this.enableHookDetection = true,
    this.enableIntegrityVerification = true,
    this.enableMemoryProtection = true,
    this.enableNetworkInterceptionDetection = true,
    this.enableWatermark = true,
    this.enableBlurOnCapture = true,
    this.enableContentEncryption = true,
    this.enableAuditLogging = true,
    this.enableClipboardGuard = true,
    this.enableDrm = false,
    this.clipboardAutoClearDelayMs = 30000,
    this.drmLicenseServerUrl,
    this.enableCertificatePinning = true,
    this.enableRasp = true,
    this.pinnedCertificates = const {},
    this.monitoringIntervalMs = 50,
    this.blurSigma = 30.0,
    this.watermarkOpacity = 0.08,
    this.watermarkUserIdentifier = '',
    this.watermarkDisplayName = '',
    this.terminateOnCritical = true,
  });

  // ─── Protection Toggles ───

  /// Block screenshots and screen recording at OS level.
  final bool enableScreenCaptureProtection;

  /// Detect and respond to debugger attachment.
  final bool enableAntiDebugging;

  /// Detect rooted (Android) / jailbroken (iOS) devices.
  final bool enableRootDetection;

  /// Detect emulators and virtual machines.
  final bool enableEmulatorDetection;

  /// Detect function hooking frameworks (Frida, Xposed).
  final bool enableHookDetection;

  /// Verify app binary integrity at runtime.
  final bool enableIntegrityVerification;

  /// Monitor and protect application memory.
  final bool enableMemoryProtection;

  /// Detect MITM proxies and traffic interception.
  final bool enableNetworkInterceptionDetection;

  /// Show visible watermark overlay (email/name/timestamp).
  final bool enableWatermark;

  /// Apply blur effect when capture is detected.
  final bool enableBlurOnCapture;

  // ─── Phase 9: Content Protection ───

  /// Encrypt content at rest using AES-256-GCM via Rust FFI.
  final bool enableContentEncryption;

  /// Record audit trail for all content viewing sessions.
  final bool enableAuditLogging;

  /// Monitor and clear clipboard to prevent content leaking via copy/paste.
  final bool enableClipboardGuard;

  /// Use platform DRM (Widevine/FairPlay) for hardware-backed decryption.
  /// Disabled by default — requires a license server.
  final bool enableDrm;

  /// How long (ms) before auto-clearing clipboard after a copy event.
  /// Only used when [enableClipboardGuard] is true. Default: 30 seconds.
  final int clipboardAutoClearDelayMs;

  /// DRM license server URL. Required when [enableDrm] is true.
  final String? drmLicenseServerUrl;

  // ─── Phase 10: Hardening ───

  /// Verify server certificates against pinned SPKI SHA-256 hashes.
  final bool enableCertificatePinning;

  /// Enable RASP (Runtime Application Self-Protection) engine.
  /// Ties all security layers together with autonomous threat response.
  final bool enableRasp;

  /// Pinned certificate hashes per host.
  /// Key: hostname, Value: Set of base64-encoded SHA-256 SPKI hashes.
  final Map<String, Set<String>> pinnedCertificates;

  // ─── Parameters ───

  /// How often (ms) the native monitoring loop checks for threats.
  /// Lower = faster detection but more CPU. Default: 50ms.
  final int monitoringIntervalMs;

  /// Gaussian blur sigma applied when capture detected. Default: 30.
  final double blurSigma;

  /// Watermark text opacity. 0.0 = invisible, 1.0 = fully opaque. Default: 0.08.
  final double watermarkOpacity;

  /// User identifier displayed in watermark (e.g., email address).
  final String watermarkUserIdentifier;

  /// User display name for watermark overlay.
  final String watermarkDisplayName;

  /// Kill the process on critical security events. Default: true.
  final bool terminateOnCritical;

  /// Maximum protection preset — all layers enabled, fastest polling.
  static const SecurityConfig maximum = SecurityConfig(
    monitoringIntervalMs: 25,
    blurSigma: 50.0,
    terminateOnCritical: true,
  );

  /// Convert to platform channel map for native initialization.
  Map<String, dynamic> toMap() {
    return {
      'enableScreenCaptureProtection': enableScreenCaptureProtection,
      'enableAntiDebugging': enableAntiDebugging,
      'enableRootDetection': enableRootDetection,
      'enableEmulatorDetection': enableEmulatorDetection,
      'enableHookDetection': enableHookDetection,
      'enableIntegrityVerification': enableIntegrityVerification,
      'enableMemoryProtection': enableMemoryProtection,
      'enableNetworkInterceptionDetection': enableNetworkInterceptionDetection,
      'enableWatermark': enableWatermark,
      'enableBlurOnCapture': enableBlurOnCapture,
      'enableContentEncryption': enableContentEncryption,
      'enableAuditLogging': enableAuditLogging,
      'enableClipboardGuard': enableClipboardGuard,
      'enableDrm': enableDrm,
      'clipboardAutoClearDelayMs': clipboardAutoClearDelayMs,
      if (drmLicenseServerUrl != null)
        'drmLicenseServerUrl': drmLicenseServerUrl,
      'enableCertificatePinning': enableCertificatePinning,
      'enableRasp': enableRasp,
      'monitoringIntervalMs': monitoringIntervalMs,
      'blurSigma': blurSigma,
      'watermarkOpacity': watermarkOpacity,
      'watermarkUserIdentifier': watermarkUserIdentifier,
      'watermarkDisplayName': watermarkDisplayName,
      'terminateOnCritical': terminateOnCritical,
    };
  }

  /// Create a modified copy with selected overrides.
  SecurityConfig copyWith({
    bool? enableScreenCaptureProtection,
    bool? enableAntiDebugging,
    bool? enableRootDetection,
    bool? enableEmulatorDetection,
    bool? enableHookDetection,
    bool? enableIntegrityVerification,
    bool? enableMemoryProtection,
    bool? enableNetworkInterceptionDetection,
    bool? enableWatermark,
    bool? enableBlurOnCapture,
    bool? enableContentEncryption,
    bool? enableAuditLogging,
    bool? enableClipboardGuard,
    bool? enableDrm,
    int? clipboardAutoClearDelayMs,
    String? drmLicenseServerUrl,
    bool? enableCertificatePinning,
    bool? enableRasp,
    Map<String, Set<String>>? pinnedCertificates,
    int? monitoringIntervalMs,
    double? blurSigma,
    double? watermarkOpacity,
    String? watermarkUserIdentifier,
    String? watermarkDisplayName,
    bool? terminateOnCritical,
  }) {
    return SecurityConfig(
      enableScreenCaptureProtection:
          enableScreenCaptureProtection ?? this.enableScreenCaptureProtection,
      enableAntiDebugging: enableAntiDebugging ?? this.enableAntiDebugging,
      enableRootDetection: enableRootDetection ?? this.enableRootDetection,
      enableEmulatorDetection:
          enableEmulatorDetection ?? this.enableEmulatorDetection,
      enableHookDetection: enableHookDetection ?? this.enableHookDetection,
      enableIntegrityVerification:
          enableIntegrityVerification ?? this.enableIntegrityVerification,
      enableMemoryProtection:
          enableMemoryProtection ?? this.enableMemoryProtection,
      enableNetworkInterceptionDetection: enableNetworkInterceptionDetection ??
          this.enableNetworkInterceptionDetection,
      enableWatermark: enableWatermark ?? this.enableWatermark,
      enableBlurOnCapture: enableBlurOnCapture ?? this.enableBlurOnCapture,
      enableContentEncryption:
          enableContentEncryption ?? this.enableContentEncryption,
      enableAuditLogging: enableAuditLogging ?? this.enableAuditLogging,
      enableClipboardGuard: enableClipboardGuard ?? this.enableClipboardGuard,
      enableDrm: enableDrm ?? this.enableDrm,
      clipboardAutoClearDelayMs:
          clipboardAutoClearDelayMs ?? this.clipboardAutoClearDelayMs,
      drmLicenseServerUrl:
          drmLicenseServerUrl ?? this.drmLicenseServerUrl,
      enableCertificatePinning:
          enableCertificatePinning ?? this.enableCertificatePinning,
      enableRasp: enableRasp ?? this.enableRasp,
      pinnedCertificates: pinnedCertificates ?? this.pinnedCertificates,
      monitoringIntervalMs: monitoringIntervalMs ?? this.monitoringIntervalMs,
      blurSigma: blurSigma ?? this.blurSigma,
      watermarkOpacity: watermarkOpacity ?? this.watermarkOpacity,
      watermarkUserIdentifier:
          watermarkUserIdentifier ?? this.watermarkUserIdentifier,
      watermarkDisplayName: watermarkDisplayName ?? this.watermarkDisplayName,
      terminateOnCritical: terminateOnCritical ?? this.terminateOnCritical,
    );
  }
}