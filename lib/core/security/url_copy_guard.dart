import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Prevents protected content from leaking through clipboard operations.
///
/// ## Why clipboard protection matters:
///
/// Even with screenshot blocking and watermarks, users can still:
/// 1. Copy decrypted text content from the app
/// 2. Copy protected content URLs (which may contain auth tokens)
/// 3. Share clipboard content with other apps
///
/// On a compromised device, malicious apps can monitor the clipboard
/// continuously (especially on Android < 12 where any app can read it).
///
/// ## Protection layers:
///
/// ### 1. Clipboard monitoring (native)
/// On Android/iOS/macOS, the native plugin registers a clipboard change
/// listener. When secure mode is active and the clipboard changes,
/// the native side can clear it after a configurable delay.
///
/// ### 2. Copy event interception (web)
/// On web, security_guard.js already blocks copy/cut keyboard shortcuts
/// and right-click → Copy. This guard adds Dart-level clipboard clearing
/// as a defense-in-depth measure.
///
/// ### 3. Automatic clipboard scrubbing
/// When secure mode exits, the guard clears the clipboard to ensure
/// no protected content lingers after the session ends.
///
/// ## Platform behavior:
///
/// | Platform | Clipboard monitoring | Auto-clear | Copy blocking |
/// |----------|---------------------|------------|---------------|
/// | Android  | ClipboardManager    | Yes        | Via FLAG_SECURE |
/// | iOS      | UIPasteboard        | Yes        | Via secure mode |
/// | macOS    | NSPasteboard        | Yes        | Via secure mode |
/// | Web      | Clipboard API       | Yes        | Via JS events |
class UrlCopyGuard {
  UrlCopyGuard._();

  static final UrlCopyGuard instance = UrlCopyGuard._();

  /// MethodChannel for native clipboard operations.
  ///
  /// Native side handles:
  /// - 'enableClipboardGuard': Start monitoring clipboard changes
  /// - 'disableClipboardGuard': Stop monitoring
  /// - 'clearClipboard': Force clear the system clipboard
  /// - 'getClipboardContent': Read current clipboard (for pattern matching)
  static const _channel =
      MethodChannel('com.cyberguard.security/clipboard');

  bool _active = false;
  Timer? _scrubTimer;

  /// Patterns that indicate sensitive content in the clipboard.
  ///
  /// If the clipboard contains text matching any of these patterns,
  /// it will be cleared automatically. Patterns are checked as substrings
  /// (not regex) for performance.
  final List<String> _sensitivePatterns = [];

  /// How long (ms) to wait before auto-clearing the clipboard
  /// after a copy event is detected. Default: 30 seconds.
  ///
  /// Short enough to limit exposure, long enough that the user
  /// can paste into a legitimate field if needed (e.g., sharing a
  /// non-sensitive portion of content).
  int _autoClearDelayMs = 30000;

  /// Whether the guard is currently active.
  bool get isActive => _active;

  /// Activate clipboard protection.
  ///
  /// Call when entering secure content viewing mode.
  /// [sensitivePatterns] — URL fragments, content IDs, or token prefixes
  ///   that should trigger auto-clear if found in clipboard.
  /// [autoClearDelayMs] — Delay before clipboard is auto-cleared after
  ///   a copy event. Set to 0 for immediate clearing.
  Future<void> activate({
    List<String> sensitivePatterns = const [],
    int autoClearDelayMs = 30000,
  }) async {
    if (_active) return;

    _sensitivePatterns
      ..clear()
      ..addAll(sensitivePatterns);
    _autoClearDelayMs = autoClearDelayMs;
    _active = true;

    if (!kIsWeb) {
      try {
        await _channel.invokeMethod<void>('enableClipboardGuard', {
          'autoClearDelayMs': _autoClearDelayMs,
        });
      } on MissingPluginException {
        // Native clipboard guard not available — Dart-only protection.
        debugPrint('CyberGuard: Native clipboard guard not available.');
      }
    }

    // Start periodic clipboard scrubbing (checks every 5 seconds)
    _startPeriodicScrub();
  }

  /// Deactivate clipboard protection and scrub the clipboard.
  ///
  /// Call when exiting secure content viewing mode.
  /// Always clears the clipboard on deactivation to ensure no
  /// protected content lingers.
  Future<void> deactivate() async {
    if (!_active) return;

    _active = false;
    _stopPeriodicScrub();

    // Final scrub — clear anything that was copied during the session
    await clearClipboard();

    if (!kIsWeb) {
      try {
        await _channel.invokeMethod<void>('disableClipboardGuard');
      } on MissingPluginException {
        // Silently ignore.
      }
    }
  }

  /// Force clear the system clipboard.
  ///
  /// Writes an empty string to the clipboard, replacing any content.
  /// On native platforms, this goes through the MethodChannel so the
  /// native clipboard manager is also updated.
  Future<void> clearClipboard() async {
    try {
      // Dart-level clipboard clear (works on all platforms)
      await Clipboard.setData(const ClipboardData(text: ''));
    } catch (e) {
      debugPrint('CyberGuard: Clipboard clear failed: $e');
    }

    if (!kIsWeb) {
      try {
        await _channel.invokeMethod<void>('clearClipboard');
      } on MissingPluginException {
        // Dart-level clear above is sufficient.
      }
    }
  }

  /// Check clipboard and clear if it contains sensitive content.
  ///
  /// Returns true if the clipboard was cleared.
  Future<bool> scrubClipboard() async {
    if (_sensitivePatterns.isEmpty) return false;

    try {
      final data = await Clipboard.getData(Clipboard.kTextPlain);
      if (data?.text == null || data!.text!.isEmpty) return false;

      final text = data.text!;
      for (final pattern in _sensitivePatterns) {
        if (text.contains(pattern)) {
          await clearClipboard();
          return true;
        }
      }
    } catch (e) {
      // Clipboard access denied (expected on some platforms).
    }

    return false;
  }

  /// Add a sensitive pattern to watch for at runtime.
  ///
  /// Useful when new content IDs or URL tokens become available
  /// during a viewing session.
  void addSensitivePattern(String pattern) {
    if (!_sensitivePatterns.contains(pattern)) {
      _sensitivePatterns.add(pattern);
    }
  }

  /// Remove all sensitive patterns.
  void clearSensitivePatterns() {
    _sensitivePatterns.clear();
  }

  // ─── Private ───

  void _startPeriodicScrub() {
    _stopPeriodicScrub();
    _scrubTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => scrubClipboard(),
    );
  }

  void _stopPeriodicScrub() {
    _scrubTimer?.cancel();
    _scrubTimer = null;
  }
}
