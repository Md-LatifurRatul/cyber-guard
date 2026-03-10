/// CyberGuard — Defense-in-Depth Content Protection Framework.
///
/// Zero third-party security dependencies. Everything custom-built.
/// Rust via FFI for performance-critical paths.
///
/// ## Quick Start:
///
/// ```dart
/// import 'package:cyber_guard/cyber_guard.dart';
///
/// void main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await CyberGuard.initialize(
///     config: SecurityConfig.maximum.copyWith(
///       watermarkUserIdentifier: 'user@example.com',
///       watermarkDisplayName: 'John Doe',
///     ),
///   );
///   runApp(const MyApp());
/// }
///
/// // Protect any widget:
/// CyberGuard.protect(child: MySecretContent())
///
/// // Play protected video:
/// CyberGuard.videoPlayer(source: MediaSource.network('https://...'))
///
/// // View protected PDF:
/// CyberGuard.pdfViewer(source: PdfSource.network('https://...'))
///
/// // View protected images:
/// CyberGuard.imageViewer(sources: [ImageSource.network('https://...')])
/// ```
///
/// ## Security Layers (10 Independent Layers):
///
/// 1. OS-Level Secure Flags (FLAG_SECURE, NSWindow.sharingType)
/// 2. Process Monitoring (screenrecord, ffmpeg, OBS detection)
/// 3. GPU-Only Rendering (CPU can't read pixels)
/// 4. Anti-Debug / Anti-Hook (ptrace, Frida, Xposed detection)
/// 5. Root/Jailbreak Detection (multi-signal scoring)
/// 6. Visible Watermark (email/name/timestamp overlay)
/// 7. Steganographic Watermark (invisible forensic ID in pixels)
/// 8. Content Encryption (AES-256-GCM via Rust FFI)
/// 9. Web Protections (Service Worker, Canvas intercept, DevTools detect)
/// 10. RASP (Runtime Application Self-Protection — autonomous threat response)
library;

// ─── Public API (Primary Entry Point) ───
export 'api/cyber_guard_api.dart' show CyberGuard;

// ─── Source Models ───
export 'api/models/media_source.dart';
export 'api/models/player_config.dart';

// ─── Protected Viewers ───
export 'api/secure_image_viewer.dart' show SecureImageViewer;
export 'api/secure_media_player.dart' show SecureMediaPlayer;
export 'api/secure_pdf_viewer.dart' show SecurePdfViewer;

// ─── Media Engine ───
export 'media/player_state.dart' show PlayerState, PlayerStatus;
export 'media/secure_player_controller.dart' show SecurePlayerController;
export 'media/player_controls.dart' show PlayerControls;
export 'media/player_overlay.dart' show PlayerOverlay;

// ─── Document & Image Viewers ───
export 'viewers/pdf/pdf_controller.dart'
    show PdfController, RenderedPage, PageSize, PdfSearchResult;
export 'viewers/pdf/pdf_page_renderer.dart' show PdfPageRenderer;
export 'viewers/pdf/pdf_thumbnail_strip.dart' show PdfThumbnailStrip;
export 'viewers/image/cached_secure_image.dart'
    show CachedSecureImage, SecureImageCache;

// ─── Security Configuration & Events ───
export 'core/security/security_config.dart' show SecurityConfig;
export 'core/security/security_event.dart'
    show SecurityEvent, SecurityEventType, SecuritySeverity;
export 'core/security/security_state.dart' show SecurityState;

// ─── RASP Engine ───
export 'core/security/rasp_engine.dart' show RaspEngine, ThreatLevel;

// ─── UI Widgets ───
export 'ui/secure_content_widget.dart' show SecureContentWidget;
export 'ui/security_status_bar.dart' show SecurityStatusBar;
export 'ui/blur_shield.dart' show BlurShield;
export 'ui/watermark_overlay.dart' show WatermarkOverlay;

// ─── Viewers ───
export 'features/viewer/secure_viewer_screen.dart' show SecureViewerScreen;

// ─── Encryption & Key Storage ───
export 'core/encryption/content_encryptor.dart' show ContentEncryptor;
export 'core/encryption/secure_key_storage.dart' show SecureKeyStorage;
export 'core/encryption/drm_bridge.dart'
    show DrmBridge, DrmInfo, DrmSystem, DrmSession, DrmSessionState;

// ─── Audit Logging ───
export 'core/logging/audit_logger.dart' show AuditLogger, AuditEntry;

// ─── Certificate Pinning ───
export 'core/security/certificate_pinner.dart' show CertificatePinner;

// ─── Platform Detection ───
export 'platform/platform_security.dart'
    show PlatformSecurity, SecurityPlatform;
