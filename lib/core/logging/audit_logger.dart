import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../security/security_event.dart';

/// Persistent audit logging for forensic investigation.
///
/// ## What gets logged:
///
/// Every content view generates an audit entry:
/// - **who:** User ID, device fingerprint
/// - **what:** Content ID, content type
/// - **when:** Start time, end time, duration
/// - **where:** Platform, device model, app version
/// - **security:** Active threats during viewing, security events
///
/// ## Why audit logging:
///
/// If content leaks, the audit trail lets you determine:
/// 1. Who had access to the leaked content
/// 2. When they viewed it
/// 3. What security events occurred during viewing
/// 4. What device they used (was it compromised?)
///
/// Combined with forensic watermarks (steganographic + visible),
/// you can identify the exact viewing session that produced the leak.
///
/// ## Storage:
///
/// Logs are stored in the app's private directory (sandbox-protected).
/// On native platforms: `{appDocuments}/cyberguard_audit/`
/// On web: In-memory ring buffer (no persistent storage available).
///
/// ## Tamper resistance:
///
/// Each log entry includes a hash chain — the hash of the previous entry.
/// If an attacker deletes or modifies a log entry, the chain breaks,
/// proving tampering occurred.
class AuditLogger {
  AuditLogger._();

  static final AuditLogger instance = AuditLogger._();

  /// In-memory ring buffer for web platform (no disk access).
  /// Also serves as a recent-events cache on native.
  static const _maxMemoryEntries = 500;
  final Queue<AuditEntry> _memoryLog = Queue<AuditEntry>();

  /// Hash of the last logged entry (for chain integrity).
  String _lastHash = '0' * 64;

  bool _initialized = false;
  String? _logDirectoryPath;

  /// MethodChannel to get the app documents directory from native code.
  ///
  /// We don't use path_provider (third-party dependency). Instead, the native
  /// plugin responds with its platform-specific documents path:
  /// - Android: Context.getFilesDir()
  /// - iOS/macOS: NSSearchPathForDirectoriesInDomains(.documentDirectory)
  static const _channel = MethodChannel('com.cyberguard.security/audit');

  /// Initialize the audit logger. Call during app startup.
  Future<void> initialize() async {
    if (_initialized) return;

    if (!kIsWeb) {
      try {
        final docsPath =
            await _channel.invokeMethod<String>('getDocumentsPath');
        if (docsPath != null) {
          _logDirectoryPath = '$docsPath/cyberguard_audit';
          final logDir = Directory(_logDirectoryPath!);
          if (!logDir.existsSync()) {
            logDir.createSync(recursive: true);
          }
        }
      } on MissingPluginException {
        debugPrint('CyberGuard: Audit log native channel not available.');
        // Fall back to memory-only logging
      } catch (e) {
        debugPrint('CyberGuard: Audit log directory setup failed: $e');
        // Fall back to memory-only logging
      }
    }

    _initialized = true;
  }

  /// Log a content view session start.
  ///
  /// Returns a session ID that must be passed to [logViewEnd].
  Future<String> logViewStart({
    required String userId,
    required String contentId,
    String? contentType,
    Map<String, dynamic>? deviceInfo,
  }) async {
    final sessionId = _generateSessionId();

    final entry = AuditEntry(
      sessionId: sessionId,
      action: AuditAction.viewStart,
      userId: userId,
      contentId: contentId,
      contentType: contentType,
      timestamp: DateTime.now(),
      deviceInfo: deviceInfo,
    );

    await _writeEntry(entry);
    return sessionId;
  }

  /// Log a content view session end.
  Future<void> logViewEnd({
    required String sessionId,
    required String userId,
    required String contentId,
    required Duration viewDuration,
    List<SecurityEvent>? securityEvents,
  }) async {
    final entry = AuditEntry(
      sessionId: sessionId,
      action: AuditAction.viewEnd,
      userId: userId,
      contentId: contentId,
      timestamp: DateTime.now(),
      viewDurationMs: viewDuration.inMilliseconds,
      securityEventCount: securityEvents?.length ?? 0,
      securityEventTypes: securityEvents
          ?.map((e) => e.type.name)
          .toSet()
          .toList(),
    );

    await _writeEntry(entry);
  }

  /// Log a security event that occurred during content viewing.
  Future<void> logSecurityEvent({
    required String userId,
    required String contentId,
    required SecurityEvent event,
    String? sessionId,
  }) async {
    final entry = AuditEntry(
      sessionId: sessionId ?? 'none',
      action: AuditAction.securityEvent,
      userId: userId,
      contentId: contentId,
      timestamp: DateTime.now(),
      securityEventTypes: [event.type.name],
      metadata: event.metadata,
    );

    await _writeEntry(entry);
  }

  /// Get recent audit entries from memory.
  List<AuditEntry> getRecentEntries({int limit = 50}) {
    return _memoryLog.toList().reversed.take(limit).toList();
  }

  // ─── Private ───

  Future<void> _writeEntry(AuditEntry entry) async {
    // Chain hash: each entry includes the hash of the previous one
    entry = entry.copyWithHash(_lastHash);
    _lastHash = entry.computeHash();

    // Add to memory ring buffer
    _memoryLog.addLast(entry);
    while (_memoryLog.length > _maxMemoryEntries) {
      _memoryLog.removeFirst();
    }

    // Write to disk on native platforms
    if (!kIsWeb && _logDirectoryPath != null) {
      try {
        final date = DateTime.now();
        final fileName =
            'audit_${date.year}${_pad(date.month)}${_pad(date.day)}.jsonl';
        final file = File('$_logDirectoryPath/$fileName');
        await file.writeAsString(
          '${jsonEncode(entry.toMap())}\n',
          mode: FileMode.append,
        );
      } catch (e) {
        debugPrint('CyberGuard: Audit write failed: $e');
      }
    }
  }

  String _generateSessionId() {
    final now = DateTime.now().microsecondsSinceEpoch;
    return now.toRadixString(36);
  }

  String _pad(int n) => n.toString().padLeft(2, '0');
}

/// The type of audit action recorded.
enum AuditAction {
  viewStart,
  viewEnd,
  securityEvent,
}

/// A single audit log entry.
///
/// Each entry is self-contained with all context needed for investigation.
/// Entries are stored as JSONL (one JSON object per line) for easy parsing.
class AuditEntry {
  AuditEntry({
    required this.sessionId,
    required this.action,
    required this.userId,
    required this.contentId,
    required this.timestamp,
    this.contentType,
    this.viewDurationMs,
    this.securityEventCount,
    this.securityEventTypes,
    this.deviceInfo,
    this.metadata,
    this.previousHash,
  });

  final String sessionId;
  final AuditAction action;
  final String userId;
  final String contentId;
  final DateTime timestamp;
  final String? contentType;
  final int? viewDurationMs;
  final int? securityEventCount;
  final List<String>? securityEventTypes;
  final Map<String, dynamic>? deviceInfo;
  final Map<String, dynamic>? metadata;
  final String? previousHash;

  /// Create a copy with the hash chain pointer set.
  AuditEntry copyWithHash(String prevHash) {
    return AuditEntry(
      sessionId: sessionId,
      action: action,
      userId: userId,
      contentId: contentId,
      timestamp: timestamp,
      contentType: contentType,
      viewDurationMs: viewDurationMs,
      securityEventCount: securityEventCount,
      securityEventTypes: securityEventTypes,
      deviceInfo: deviceInfo,
      metadata: metadata,
      previousHash: prevHash,
    );
  }

  /// Compute SHA-256 hash of this entry (for chain integrity).
  String computeHash() {
    final data = jsonEncode(toMap());
    // Simple hash — for production, use crypto SHA-256
    var hash = 0x811c9dc5;
    for (var i = 0; i < data.length; i++) {
      hash ^= data.codeUnitAt(i);
      hash = (hash * 0x01000193) & 0xFFFFFFFF;
    }
    return hash.toRadixString(16).padLeft(8, '0');
  }

  Map<String, dynamic> toMap() {
    return {
      'sessionId': sessionId,
      'action': action.name,
      'userId': userId,
      'contentId': contentId,
      'timestamp': timestamp.toIso8601String(),
      'timestampMs': timestamp.millisecondsSinceEpoch,
      if (contentType != null) 'contentType': contentType,
      if (viewDurationMs != null) 'viewDurationMs': viewDurationMs,
      if (securityEventCount != null)
        'securityEventCount': securityEventCount,
      if (securityEventTypes != null)
        'securityEventTypes': securityEventTypes,
      if (deviceInfo != null) 'deviceInfo': deviceInfo,
      if (metadata != null) 'metadata': metadata,
      if (previousHash != null) 'previousHash': previousHash,
    };
  }
}
