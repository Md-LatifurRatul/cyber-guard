import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../core/encryption/content_encryptor.dart';
import '../core/encryption/drm_bridge.dart';
import '../core/encryption/secure_key_storage.dart';
import '../core/logging/audit_logger.dart';
import '../core/security/certificate_pinner.dart';
import '../core/security/rasp_engine.dart';
import '../core/security/security_channel.dart';
import '../core/security/security_config.dart';
import '../core/security/security_event.dart';
import '../core/security/security_state.dart';
import '../features/viewer/secure_viewer_screen.dart';
import '../ui/secure_content_widget.dart';
import '../ui/security_status_bar.dart';
import 'models/media_source.dart';
import 'models/player_config.dart';
import 'secure_image_viewer.dart';
import 'secure_media_player.dart';
import 'secure_pdf_viewer.dart';

/// CyberGuard — Defense-in-Depth Content Protection Framework.
///
/// This is the primary public API for CyberGuard. It provides a clean,
/// developer-friendly facade over the entire security framework.
///
/// ## Quick Start:
/// ```dart
/// // 1. Initialize at app startup (before runApp)
/// await CyberGuard.initialize(
///   config: SecurityConfig.maximum.copyWith(
///     watermarkUserIdentifier: user.email,
///     watermarkDisplayName: user.name,
///   ),
/// );
///
/// // 2. Protect any widget
/// CyberGuard.protect(child: MySecretContent())
///
/// // 3. Play protected video
/// CyberGuard.videoPlayer(source: MediaSource.network('https://...'))
///
/// // 4. View protected PDF
/// CyberGuard.pdfViewer(source: PdfSource.network('https://...'))
///
/// // 5. View protected images
/// CyberGuard.imageViewer(sources: [ImageSource.network('https://...')])
/// ```
///
/// ## How it works:
///
/// Every widget returned by CyberGuard is automatically wrapped with:
/// 1. **Native secure flags** (FLAG_SECURE, NSWindow.sharingType, etc.)
/// 2. **Visible watermark** (email/name/timestamp)
/// 3. **Blur shield** (activates on threat detection)
/// 4. **RASP monitoring** (real-time threat scoring + response)
/// 5. **Audit logging** (who viewed what, when, from where)
///
/// You never need to manage security lifecycle manually — CyberGuard
/// handles enter/exit secure mode, clipboard guard, key management,
/// and emergency response automatically.
///
/// ## Architecture:
/// ```
/// CyberGuard (you are here)
///     │
///     ├── SecurityChannel  → native platform flags
///     ├── RaspEngine       → threat scoring + auto-response
///     ├── AuditLogger      → forensic audit trail
///     ├── ContentEncryptor  → AES-256-GCM via Rust FFI
///     ├── SecureKeyStorage  → hardware-backed keys (TEE/Keychain)
///     ├── CertificatePinner → TLS certificate pinning
///     ├── UrlCopyGuard      → clipboard monitoring
///     └── DrmBridge         → Widevine/FairPlay/EME
/// ```
class CyberGuard {
  CyberGuard._();

  static bool _initialized = false;

  // ─── Initialization ───

  /// Initialize the CyberGuard security framework.
  ///
  /// **Must be called before `runApp()`** to ensure native protection
  /// flags are active before any frame is rendered.
  ///
  /// ```dart
  /// void main() async {
  ///   WidgetsFlutterBinding.ensureInitialized();
  ///   await CyberGuard.initialize();
  ///   runApp(const MyApp());
  /// }
  /// ```
  ///
  /// [config] — Security configuration. Defaults to [SecurityConfig.maximum].
  /// [enableRasp] — Whether to start the RASP engine. Default: true.
  /// [pinnedCertificates] — TLS certificate pins per host.
  static Future<void> initialize({
    SecurityConfig config = const SecurityConfig(),
    bool enableRasp = true,
    Map<String, Set<String>>? pinnedCertificates,
  }) async {
    if (_initialized) return;

    // Initialize the core security channel (native bridge)
    await SecurityChannel.instance.initialize(config);

    // Initialize RASP engine (threat scoring + auto-response)
    if (enableRasp && config.enableRasp) {
      await RaspEngine.instance.initialize(config);
    }

    // Configure certificate pinning
    if (pinnedCertificates != null && pinnedCertificates.isNotEmpty) {
      CertificatePinner.instance.configure(pinnedCertificates);
    }

    _initialized = true;
  }

  /// Whether CyberGuard has been initialized.
  static bool get isInitialized => _initialized;

  /// The current security configuration.
  static SecurityConfig get config => SecurityChannel.instance.config;

  // ─── Content Protection Widgets ───

  /// Wrap any widget with full CyberGuard protection.
  ///
  /// Applies all active security layers:
  /// - Native secure mode (FLAG_SECURE, etc.)
  /// - Visible watermark overlay
  /// - Blur shield on threat detection
  ///
  /// ```dart
  /// CyberGuard.protect(
  ///   child: Text('Top Secret'),
  /// )
  /// ```
  static Widget protect({
    required Widget child,
    SecurityConfig? config,
    void Function(SecurityState state)? onSecurityEvent,
    Key? key,
  }) {
    return SecureContentWidget(
      key: key,
      config: config,
      onSecurityEvent: onSecurityEvent,
      child: child,
    );
  }

  /// Open a full-screen secure viewer for any content.
  ///
  /// Wraps the child in a Scaffold with app bar, security status
  /// indicator, and all protection layers.
  ///
  /// ```dart
  /// Navigator.push(context, MaterialPageRoute(
  ///   builder: (_) => CyberGuard.fullScreenViewer(
  ///     title: 'Confidential Report',
  ///     child: MyReportWidget(),
  ///   ),
  /// ));
  /// ```
  static Widget fullScreenViewer({
    required Widget child,
    String title = 'Secure Content',
    bool showStatusBar = true,
    Color? backgroundColor,
    Key? key,
  }) {
    return SecureViewerScreen(
      key: key,
      title: title,
      showStatusBar: showStatusBar,
      backgroundColor: backgroundColor,
      child: child,
    );
  }

  /// Create a protected video/audio player.
  ///
  /// Supports all major formats: MP4, 3GP, WebM, MKV, MOV, AVI, FLV,
  /// HLS (.m3u8), DASH (.mpd), RTMP (live), and audio (MP3, AAC, OGG).
  ///
  /// ```dart
  /// CyberGuard.videoPlayer(
  ///   source: MediaSource.network('https://example.com/video.mp4'),
  ///   config: const PlayerConfig(autoPlay: true),
  /// )
  /// ```
  static Widget videoPlayer({
    required MediaSource source,
    PlayerConfig config = const PlayerConfig(),
    Key? key,
  }) {
    return SecureMediaPlayer(
      key: key,
      source: source,
      config: config,
    );
  }

  /// Create a protected PDF document viewer.
  ///
  /// Renders PDF pages natively with zoom, search, thumbnails,
  /// and night mode support.
  ///
  /// ```dart
  /// CyberGuard.pdfViewer(
  ///   source: PdfSource.network('https://example.com/report.pdf'),
  /// )
  /// ```
  static Widget pdfViewer({
    required PdfSource source,
    PdfViewerConfig config = const PdfViewerConfig(),
    Key? key,
  }) {
    return SecurePdfViewer(
      key: key,
      source: source,
      config: config,
    );
  }

  /// Create a protected image viewer/gallery.
  ///
  /// Supports single image or multi-image gallery with pinch-to-zoom,
  /// double-tap zoom, and swipe navigation.
  ///
  /// ```dart
  /// // Single image
  /// CyberGuard.imageViewer(
  ///   sources: [ImageSource.network('https://cdn.example.com/photo.jpg')],
  /// )
  ///
  /// // Gallery
  /// CyberGuard.imageViewer(
  ///   sources: [
  ///     ImageSource.network('https://cdn.example.com/1.jpg'),
  ///     ImageSource.network('https://cdn.example.com/2.jpg'),
  ///     ImageSource.network('https://cdn.example.com/3.jpg'),
  ///   ],
  ///   config: const ImageViewerConfig(initialIndex: 0),
  /// )
  /// ```
  static Widget imageViewer({
    required List<ImageSource> sources,
    ImageViewerConfig config = const ImageViewerConfig(),
    Key? key,
  }) {
    return SecureImageViewer(
      key: key,
      sources: sources,
      config: config,
    );
  }

  // ─── Security Status ───

  /// Get the current security state snapshot.
  ///
  /// Returns the real-time threat state including:
  /// - Whether screen is being captured
  /// - Debugger attachment status
  /// - Root/jailbreak detection
  /// - Active threats list
  static SecurityState get currentState =>
      SecurityChannel.instance.currentState;

  /// Stream of security state changes.
  ///
  /// Listen to react to security events in your UI:
  /// ```dart
  /// CyberGuard.stateStream.listen((state) {
  ///   if (state.shouldBlurContent) {
  ///     // Threat detected — content is being blurred
  ///   }
  /// });
  /// ```
  static Stream<SecurityState> get stateStream =>
      SecurityChannel.instance.stateStream;

  /// Stream of raw security events.
  ///
  /// Lower-level than [stateStream] — fires for every individual event
  /// (screen capture, debugger, root detection, etc.).
  static Stream<SecurityEvent> get eventStream =>
      SecurityChannel.instance.eventStream;

  /// The current RASP threat level.
  static ThreatLevel get threatLevel => RaspEngine.instance.threatLevel;

  /// The current RASP threat score.
  static int get threatScore => RaspEngine.instance.threatScore;

  /// A compact security status indicator widget.
  ///
  /// Shows a colored shield icon reflecting current security state.
  /// Use [compact: false] for a detailed status bar with text.
  static Widget statusIndicator({bool compact = true, Key? key}) {
    return SecurityStatusBar(key: key, compact: compact);
  }

  // ─── Protected Mode (Session Management) ───

  /// Enter a protected content viewing session.
  ///
  /// Activates all protection layers and starts audit logging.
  /// Returns a session ID for audit trail linking.
  ///
  /// Call [exitProtectedMode] when the user finishes viewing.
  ///
  /// ```dart
  /// final sessionId = await CyberGuard.enterProtectedMode(
  ///   userId: user.id,
  ///   contentId: 'report-2024-Q4',
  /// );
  /// // ... user views content ...
  /// await CyberGuard.exitProtectedMode(
  ///   sessionId: sessionId,
  ///   userId: user.id,
  ///   contentId: 'report-2024-Q4',
  ///   viewDuration: stopwatch.elapsed,
  /// );
  /// ```
  static Future<String> enterProtectedMode({
    required String userId,
    required String contentId,
    String? contentType,
    Map<String, dynamic>? deviceInfo,
  }) {
    return RaspEngine.instance.enterProtectedMode(
      userId: userId,
      contentId: contentId,
      contentType: contentType,
      deviceInfo: deviceInfo,
    );
  }

  /// Exit a protected content viewing session.
  ///
  /// Deactivates protection layers and logs the session end.
  static Future<void> exitProtectedMode({
    required String sessionId,
    required String userId,
    required String contentId,
    required Duration viewDuration,
  }) {
    return RaspEngine.instance.exitProtectedMode(
      sessionId: sessionId,
      userId: userId,
      contentId: contentId,
      viewDuration: viewDuration,
    );
  }

  // ─── Encryption ───

  /// Access the content encryptor for AES-256-GCM operations.
  ///
  /// Provides encrypt, decrypt, key generation, and memory zeroing.
  /// Uses Rust FFI for performance-critical crypto operations.
  ///
  /// ```dart
  /// final encryptor = CyberGuard.encryptor;
  /// final key = encryptor.generateKey();
  /// final encrypted = encryptor.encryptContent(key, plaintext);
  /// final decrypted = encryptor.decryptContent(key, encrypted!);
  /// encryptor.zeroBuffer(decrypted!); // MANDATORY after rendering
  /// ```
  static ContentEncryptor get encryptor => ContentEncryptor.instance;

  // ─── Key Storage ───

  /// Store a key in platform-secure storage (TEE/Keychain/memory).
  static Future<bool> storeKey(String keyId, Uint8List key) {
    return SecureKeyStorage.instance.storeKey(keyId, key);
  }

  /// Retrieve a key from platform-secure storage.
  static Future<Uint8List?> retrieveKey(String keyId) {
    return SecureKeyStorage.instance.retrieveKey(keyId);
  }

  /// Delete a key from platform-secure storage.
  static Future<bool> deleteKey(String keyId) {
    return SecureKeyStorage.instance.deleteKey(keyId);
  }

  // ─── DRM ───

  /// Get platform DRM capabilities (Widevine, FairPlay, EME).
  static Future<DrmInfo> getDrmInfo() {
    return DrmBridge.instance.getDrmInfo();
  }

  // ─── Audit ───

  /// Get recent audit log entries.
  static List<AuditEntry> getAuditLog({int limit = 50}) {
    return AuditLogger.instance.getRecentEntries(limit: limit);
  }

  // ─── Lifecycle ───

  /// Shut down CyberGuard and release all resources.
  ///
  /// Call on app termination or logout. Performs:
  /// - RASP engine shutdown
  /// - DRM session release
  /// - Security channel disposal
  /// - Key storage cleanup
  static Future<void> dispose() async {
    await RaspEngine.instance.dispose();
    await DrmBridge.instance.releaseAll();
    await SecurityChannel.instance.dispose();
    _initialized = false;
  }
}
