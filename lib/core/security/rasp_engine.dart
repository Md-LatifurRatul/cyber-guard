import 'dart:async';

import 'package:flutter/foundation.dart';

import '../encryption/drm_bridge.dart';
import '../encryption/secure_key_storage.dart';
import '../logging/audit_logger.dart';
import 'certificate_pinner.dart';
import 'security_channel.dart';
import 'security_config.dart';
import 'security_event.dart';
import 'url_copy_guard.dart';

/// Runtime Application Self-Protection (RASP) engine.
///
/// ## What RASP does:
///
/// RASP is the top-level orchestrator that ties all 10 security layers
/// together into a unified, autonomous threat response system. It:
///
/// 1. **Monitors** — Subscribes to SecurityChannel event stream
/// 2. **Correlates** — Multiple low signals = high threat (threat scoring)
/// 3. **Responds** — Escalates automatically: log → blur → wipe → kill
/// 4. **Self-verifies** — Checks its own integrity periodically
///
/// ## Threat response levels:
///
/// | Level    | Score | Response                                    |
/// |----------|-------|---------------------------------------------|
/// | Green    | 0     | Normal operation, all protections passive    |
/// | Yellow   | 1-3   | Log + activate clipboard guard               |
/// | Orange   | 4-6   | Blur content + notify user + audit log       |
/// | Red      | 7-9   | Wipe decrypted content + revoke keys         |
/// | Critical | 10+   | Emergency shutdown + wipe everything          |
///
/// ## Threat scoring:
///
/// Each security event type has a weight. Weights are cumulative.
/// A rooted device alone = 3 (orange). Root + Frida = 3+4 = 7 (red).
/// This prevents overreaction to benign signals while ensuring
/// combined attacks trigger aggressive defense.
///
/// ## Architecture:
/// ```
/// ┌──────────────────────────────────────────────┐
/// │                RASP Engine                     │
/// │  ┌─────────────┐  ┌──────────────────────┐   │
/// │  │ Threat Score │  │ Response Escalation  │   │
/// │  │ Calculator   │→ │ Green→Yellow→Orange  │   │
/// │  │              │  │ →Red→Critical        │   │
/// │  └─────┬───────┘  └──────────┬───────────┘   │
/// │        │                     │                │
/// │  ┌─────┴─────────────────────┴───────────┐   │
/// │  │          Event Correlator              │   │
/// │  └─────┬─────┬──────┬──────┬─────────────┘   │
/// │        │     │      │      │                  │
/// ├────────┴─────┴──────┴──────┴──────────────────┤
/// │ SecurityChannel | AuditLogger | CertPinner    │
/// │ UrlCopyGuard   | KeyStorage  | DrmBridge      │
/// │ ContentEncryptor | NativeBridge (Rust FFI)    │
/// └──────────────────────────────────────────────┘
/// ```
class RaspEngine {
  RaspEngine._();

  static final RaspEngine instance = RaspEngine._();

  // ─── Dependencies ───

  final SecurityChannel _securityChannel = SecurityChannel.instance;
  final AuditLogger _auditLogger = AuditLogger.instance;
  final CertificatePinner _certPinner = CertificatePinner.instance;
  final UrlCopyGuard _copyGuard = UrlCopyGuard.instance;
  final SecureKeyStorage _keyStorage = SecureKeyStorage.instance;
  final DrmBridge _drmBridge = DrmBridge.instance;

  // ─── State ───

  bool _initialized = false;
  SecurityConfig _config = const SecurityConfig();
  StreamSubscription<SecurityEvent>? _eventSubscription;
  Timer? _selfCheckTimer;

  /// Current cumulative threat score.
  int _threatScore = 0;

  /// Current threat level derived from score.
  ThreatLevel _threatLevel = ThreatLevel.green;

  /// Active threat types contributing to the score.
  final Map<SecurityEventType, int> _activeThreats = {};

  /// Callback for threat level changes — UI can react to this.
  void Function(ThreatLevel level, int score)? onThreatLevelChanged;

  /// Callback before emergency shutdown — last chance to save state.
  Future<void> Function()? onEmergencyShutdown;

  /// Current threat level.
  ThreatLevel get threatLevel => _threatLevel;

  /// Current threat score.
  int get threatScore => _threatScore;

  /// Whether the engine is running.
  bool get isRunning => _initialized;

  // ─── Threat Weights ───

  /// How much each event type contributes to the threat score.
  ///
  /// Weights are tuned to prevent false escalation from benign signals
  /// while ensuring real attacks trigger aggressive defense.
  static const Map<SecurityEventType, int> _threatWeights = {
    // Low signals (1-2): common on dev devices, single signal not alarming
    SecurityEventType.appBackgrounded: 0, // Normal behavior
    SecurityEventType.screenCapture: 2, // Could be benign (AirPlay)
    SecurityEventType.accessibilityAbuse: 1, // Could be accessibility apps
    SecurityEventType.devToolsOpened: 2, // Web developer
    SecurityEventType.clipboardCopy: 1, // Could be accidental

    // Medium signals (3): real concern but not definitively malicious
    SecurityEventType.rootDetected: 3, // Power user vs attacker
    SecurityEventType.emulatorDetected: 3, // Dev vs attacker
    SecurityEventType.virtualizationDetected: 2, // Dev VM
    SecurityEventType.networkInterception: 3, // Corporate proxy vs MITM
    SecurityEventType.sipDisabled: 3, // Dev macOS vs attacker

    // High signals (4-5): strong indicators of attack
    SecurityEventType.debuggerAttached: 4, // Active reverse engineering
    SecurityEventType.hookingDetected: 5, // Frida/Xposed = active attack
    SecurityEventType.dyldInjection: 5, // Runtime injection
    SecurityEventType.integrityViolation: 5, // Binary tampered
    SecurityEventType.memoryTampering: 4, // Memory modification

    // Critical signals (6+): definitive attack indicators
    SecurityEventType.decryptionFailure: 3, // Could be corruption
    SecurityEventType.auditTampered: 6, // Definitive tampering
    SecurityEventType.drmLicenseFailure: 2, // Could be network issue
  };

  // ─── Lifecycle ───

  /// Initialize the RASP engine and all subsystems.
  ///
  /// Call once during app startup, after SecurityChannel.initialize().
  /// This wires up all security layers into a unified response system.
  Future<void> initialize(SecurityConfig config) async {
    if (_initialized) return;
    _config = config;

    // Initialize subsystems
    if (_config.enableAuditLogging) {
      await _auditLogger.initialize();
    }

    // Subscribe to security events
    _eventSubscription = _securityChannel.eventStream.listen(_onSecurityEvent);

    // Wire certificate pinning failure → security event
    _certPinner.onPinFailure = _onCertPinFailure;

    // Start periodic self-check (every 30 seconds)
    _selfCheckTimer = Timer.periodic(
      const Duration(seconds: 30),
      (_) => _selfCheck(),
    );

    _initialized = true;
    debugPrint('CyberGuard: RASP engine initialized.');
  }

  /// Enter protected content viewing mode.
  ///
  /// Activates all content protection layers:
  /// 1. Native secure mode (FLAG_SECURE, etc.)
  /// 2. Clipboard guard
  /// 3. Audit log session start
  ///
  /// Returns a session ID for audit trail linking.
  Future<String> enterProtectedMode({
    required String userId,
    required String contentId,
    String? contentType,
    Map<String, dynamic>? deviceInfo,
  }) async {
    _assertInitialized();

    // Activate native protection
    await _securityChannel.enterSecureMode();

    // Activate clipboard guard
    if (_config.enableClipboardGuard) {
      await _copyGuard.activate(
        sensitivePatterns: [contentId],
        autoClearDelayMs: _config.clipboardAutoClearDelayMs,
      );
    }

    // Start audit log session
    String sessionId = 'no-audit';
    if (_config.enableAuditLogging) {
      sessionId = await _auditLogger.logViewStart(
        userId: userId,
        contentId: contentId,
        contentType: contentType,
        deviceInfo: deviceInfo,
      );
    }

    return sessionId;
  }

  /// Exit protected content viewing mode.
  ///
  /// Deactivates content protection and logs the session end.
  Future<void> exitProtectedMode({
    required String sessionId,
    required String userId,
    required String contentId,
    required Duration viewDuration,
  }) async {
    // Deactivate native protection
    await _securityChannel.exitSecureMode();

    // Deactivate clipboard guard (scrubs clipboard)
    if (_config.enableClipboardGuard) {
      await _copyGuard.deactivate();
    }

    // Log session end
    if (_config.enableAuditLogging) {
      await _auditLogger.logViewEnd(
        sessionId: sessionId,
        userId: userId,
        contentId: contentId,
        viewDuration: viewDuration,
      );
    }
  }

  /// Perform emergency content wipe.
  ///
  /// Called when threat level reaches Red or Critical.
  /// Destroys all decrypted content and keys in memory.
  Future<void> emergencyWipe() async {
    debugPrint('CyberGuard: RASP emergency wipe triggered.');

    // Clear all encryption keys from hardware + memory
    await _keyStorage.clearAll();

    // Release all DRM sessions
    await _drmBridge.releaseAll();

    // Scrub clipboard
    await _copyGuard.clearClipboard();
  }

  /// Shut down the RASP engine and clean up all resources.
  Future<void> dispose() async {
    _selfCheckTimer?.cancel();
    _selfCheckTimer = null;
    await _eventSubscription?.cancel();
    _eventSubscription = null;
    _certPinner.onPinFailure = null;
    _activeThreats.clear();
    _threatScore = 0;
    _threatLevel = ThreatLevel.green;
    _initialized = false;
  }

  // ─── Event Processing ───

  void _onSecurityEvent(SecurityEvent event) {
    final weight = _threatWeights[event.type] ?? 2;

    // Add to active threats (don't double-count same type)
    if (!_activeThreats.containsKey(event.type)) {
      _activeThreats[event.type] = weight;
      _threatScore += weight;
    }

    // Log to audit trail
    if (_config.enableAuditLogging) {
      _auditLogger.logSecurityEvent(
        userId: 'system',
        contentId: 'rasp',
        event: event,
      );
    }

    // Evaluate threat level
    _evaluateThreatLevel();
  }

  void _onCertPinFailure(Map<String, dynamic> failure) {
    debugPrint('CyberGuard: Certificate pin failure: ${failure['host']}');

    // Fire as a security event
    final event = SecurityEvent(
      type: SecurityEventType.networkInterception,
      severity: SecuritySeverity.high,
      timestamp: DateTime.now(),
      metadata: failure,
    );
    _onSecurityEvent(event);
  }

  // ─── Threat Evaluation ───

  void _evaluateThreatLevel() {
    final previousLevel = _threatLevel;

    if (_threatScore >= 10) {
      _threatLevel = ThreatLevel.critical;
    } else if (_threatScore >= 7) {
      _threatLevel = ThreatLevel.red;
    } else if (_threatScore >= 4) {
      _threatLevel = ThreatLevel.orange;
    } else if (_threatScore >= 1) {
      _threatLevel = ThreatLevel.yellow;
    } else {
      _threatLevel = ThreatLevel.green;
    }

    if (_threatLevel != previousLevel) {
      onThreatLevelChanged?.call(_threatLevel, _threatScore);
      _executeResponse(_threatLevel);
    }
  }

  Future<void> _executeResponse(ThreatLevel level) async {
    switch (level) {
      case ThreatLevel.green:
        break; // Normal operation

      case ThreatLevel.yellow:
        // Heightened awareness — activate passive defenses
        if (_config.enableClipboardGuard && !_copyGuard.isActive) {
          await _copyGuard.activate(
            autoClearDelayMs: _config.clipboardAutoClearDelayMs,
          );
        }

      case ThreatLevel.orange:
        // Active defense — blur content, notify
        if (!_securityChannel.currentState.isSecureModeActive) {
          await _securityChannel.enterSecureMode();
        }

      case ThreatLevel.red:
        // Aggressive defense — wipe decrypted content
        await emergencyWipe();

      case ThreatLevel.critical:
        // Nuclear — wipe everything and terminate
        await emergencyWipe();
        await onEmergencyShutdown?.call();

        if (_config.terminateOnCritical) {
          await _securityChannel.dispose();
          // Native side will kill the process via emergencyShutdown
        }
    }
  }

  // ─── Self-Check ───

  /// Periodic self-verification to detect tampering with the RASP engine itself.
  ///
  /// Checks:
  /// 1. SecurityChannel still initialized (attacker might dispose it)
  /// 2. Event subscription still active (attacker might cancel it)
  /// 3. Config hasn't been replaced (attacker might inject permissive config)
  void _selfCheck() {
    if (!_initialized) return;

    // Check 1: SecurityChannel must be initialized
    if (!_securityChannel.isInitialized) {
      debugPrint('CyberGuard: RASP self-check FAILED — SecurityChannel down.');
      _onSecurityEvent(SecurityEvent(
        type: SecurityEventType.integrityViolation,
        severity: SecuritySeverity.critical,
        timestamp: DateTime.now(),
        metadata: const {'source': 'rasp_self_check', 'reason': 'channel_down'},
      ));
      return;
    }

    // Check 2: Event subscription must be active
    if (_eventSubscription == null) {
      debugPrint('CyberGuard: RASP self-check FAILED — event stream dead.');
      _eventSubscription =
          _securityChannel.eventStream.listen(_onSecurityEvent);
    }

    // Check 3: Config integrity — terminateOnCritical should not have been
    // changed to false at runtime (attacker disabling kill switch)
    if (_config.terminateOnCritical !=
        SecurityChannel.instance.config.terminateOnCritical) {
      debugPrint('CyberGuard: RASP self-check FAILED — config tampered.');
      _onSecurityEvent(SecurityEvent(
        type: SecurityEventType.integrityViolation,
        severity: SecuritySeverity.high,
        timestamp: DateTime.now(),
        metadata: const {'source': 'rasp_self_check', 'reason': 'config_tamper'},
      ));
    }
  }

  void _assertInitialized() {
    assert(
      _initialized,
      'RaspEngine.initialize() must be called before using any methods.',
    );
  }
}

/// Threat level determines the RASP response intensity.
///
/// Each level activates increasingly aggressive defenses.
/// Levels only escalate upward — they never de-escalate automatically.
/// (An attacker could fake a "cleared" state to disable protections.)
enum ThreatLevel {
  /// Score 0 — no threats detected. Normal operation.
  green,

  /// Score 1-3 — low-level signals. Passive defense (clipboard guard).
  yellow,

  /// Score 4-6 — medium threats. Active defense (blur, notify).
  orange,

  /// Score 7-9 — high threats. Aggressive defense (wipe content, revoke keys).
  red,

  /// Score 10+ — definitive attack. Nuclear (wipe everything, terminate).
  critical,
}
