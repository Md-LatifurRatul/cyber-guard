/// All possible security threat types detected by the framework.
///
/// Each event type represents an independent security signal.
/// Multiple signals can fire simultaneously (e.g., root + debugger).
enum SecurityEventType {
  /// Screen capture or recording detected (screenshot, screen record, mirroring).
  screenCapture,

  /// Debugger (LLDB, GDB, Android Studio debugger) attached to the process.
  debuggerAttached,

  /// Application memory has been modified externally (Cheat Engine, GameGuardian).
  memoryTampering,

  /// Device is rooted (Android) or jailbroken (iOS).
  rootDetected,

  /// Application is running inside an emulator or virtual machine.
  emulatorDetected,

  /// Hypervisor or virtualization layer detected (VirtualBox, QEMU).
  virtualizationDetected,

  /// Network traffic is being intercepted (MITM proxy like Charles, mitmproxy).
  networkInterception,

  /// Function hooking framework detected (Frida, Xposed, Substrate).
  hookingDetected,

  /// App binary has been tampered with (re-signed, patched, modified).
  integrityViolation,

  /// Accessibility service is reading screen content.
  accessibilityAbuse,

  /// App has been backgrounded (potential for task switcher screenshot).
  appBackgrounded,

  /// DevTools opened in web browser.
  devToolsOpened,

  // ─── Phase 9: Content Protection Events ───

  /// Content was copied to clipboard while in secure mode.
  clipboardCopy,

  /// Content decryption failed (wrong key, tampered data, or auth tag mismatch).
  decryptionFailure,

  /// Audit log hash chain broken — indicates log tampering.
  auditTampered,

  /// DRM license acquisition failed or was revoked.
  drmLicenseFailure,

  /// Injected DYLD library detected at runtime (Frida, Substrate, etc.).
  dyldInjection,

  /// System Integrity Protection (SIP) is disabled on macOS.
  sipDisabled,

  // ─── Phase 10: Hardening Events ───

  /// TLS certificate pin validation failed — potential MITM attack.
  certificatePinFailure,

  /// RASP self-check detected tampering with security engine itself.
  raspTampered,
}

/// Severity level determines the response intensity.
enum SecuritySeverity {
  /// Informational — log only, no action required.
  low,

  /// Warning — apply blur, notify user.
  medium,

  /// Critical — immediate content wipe and session termination.
  high,

  /// Emergency — kill process immediately.
  critical,
}

/// Immutable representation of a security event.
///
/// Created by native platform code and streamed to Dart via EventChannel.
/// Each event carries a type, severity, timestamp, and optional metadata
/// for forensic logging.
class SecurityEvent {
  const SecurityEvent({
    required this.type,
    required this.severity,
    required this.timestamp,
    this.metadata = const {},
  });

  final SecurityEventType type;
  final SecuritySeverity severity;
  final DateTime timestamp;
  final Map<String, dynamic> metadata;

  /// Deserialize from platform channel map.
  ///
  /// Native code sends: {'type': 'screenCapture', 'severity': 'high',
  ///   'timestamp': 1234567890, 'metadata': {...}}
  factory SecurityEvent.fromPlatformMap(Map<Object?, Object?> map) {
    final typeStr = map['type'] as String? ?? '';
    final severityStr = map['severity'] as String? ?? 'high';
    final timestampMs = map['timestamp'] as int? ?? 0;
    final rawMetadata = map['metadata'];

    return SecurityEvent(
      type: _parseEventType(typeStr),
      severity: _parseSeverity(severityStr),
      timestamp: DateTime.fromMillisecondsSinceEpoch(timestampMs),
      metadata: rawMetadata is Map
          ? Map<String, dynamic>.from(rawMetadata)
          : const {},
    );
  }

  /// Serialize to map for logging or forwarding.
  Map<String, dynamic> toMap() {
    return {
      'type': type.name,
      'severity': severity.name,
      'timestamp': timestamp.millisecondsSinceEpoch,
      'metadata': metadata,
    };
  }

  /// Whether this event requires immediate content protection (blur/wipe).
  bool get requiresImmediateAction =>
      severity == SecuritySeverity.high ||
      severity == SecuritySeverity.critical;

  /// Whether this event should terminate the session.
  bool get requiresTermination => severity == SecuritySeverity.critical;

  static SecurityEventType _parseEventType(String value) {
    for (final type in SecurityEventType.values) {
      if (type.name == value) return type;
    }
    return SecurityEventType.integrityViolation;
  }

  static SecuritySeverity _parseSeverity(String value) {
    for (final sev in SecuritySeverity.values) {
      if (sev.name == value) return sev;
    }
    return SecuritySeverity.high;
  }

  @override
  String toString() =>
      'SecurityEvent(${type.name}, ${severity.name}, $timestamp)';
}
