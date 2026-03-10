# CyberGuard

**Defense-in-Depth Content Protection Framework for Flutter**

A comprehensive, multi-layered security framework that protects sensitive content across Android, iOS, macOS, and Web platforms. Built entirely from scratch with zero third-party security dependencies — every protection mechanism is custom-engineered, with Rust powering the performance-critical cryptographic and detection paths via FFI.

---

## Why CyberGuard?

Standard content protection relies on a single mechanism (usually just `FLAG_SECURE` or DRM). That's a single point of failure. CyberGuard takes a fundamentally different approach: **10 independent security layers** working simultaneously, so compromising one layer still leaves nine others active.

If someone bypasses screen capture prevention, they still face watermark overlays. If they strip visible watermarks, steganographic forensic IDs remain embedded in the pixel data. If they hook into the rendering pipeline, anti-hook detection triggers content blur. Every layer is autonomous.

---

## Security Layers

| # | Layer | Description | Platforms |
|---|-------|-------------|-----------|
| 1 | **OS-Level Secure Flags** | `FLAG_SECURE`, `UIScreen.isCaptured`, `NSWindow.sharingType = .none` | Android, iOS, macOS |
| 2 | **Process Monitoring** | Detects screenrecord, ffmpeg, OBS, ReplayKit, and similar tools | Android, iOS |
| 3 | **GPU-Only Rendering** | Content stays in GPU memory — CPU-based capture tools can't read pixels | All |
| 4 | **Anti-Debug / Anti-Hook** | ptrace denial, Frida/Xposed/Substrate/Cycript detection | Android, iOS, macOS |
| 5 | **Root/Jailbreak Detection** | Multi-signal scoring (su, Magisk, Cydia, sandbox escape, fork test) | Android, iOS |
| 6 | **Visible Watermark** | User email/name/timestamp overlay rendered on all protected content | All |
| 7 | **Steganographic Watermark** | Invisible forensic ID embedded directly in pixel data via Rust FFI | All |
| 8 | **Content Encryption** | AES-256-GCM with hardware-backed key storage (TEE/Secure Enclave) | All |
| 9 | **Web Protections** | Canvas/WebGL readback interception, DevTools detection, CSP headers | Web |
| 10 | **RASP Engine** | Runtime Application Self-Protection with autonomous threat scoring and response escalation | All |

---

## Platform Coverage

| Feature | Android | iOS | macOS | Web |
|---------|---------|-----|-------|-----|
| Screen capture prevention | FLAG_SECURE | UIScreen.isCaptured | NSWindow.sharingType | Canvas intercept |
| Root/Jailbreak detection | 8 signals | 7 signals | SIP check | N/A |
| Anti-debug | ptrace + JNI | PT_DENY_ATTACH | PT_DENY_ATTACH | DevTools detect |
| Hook detection | Frida/Xposed/Substrate | DYLD injection + dylib scan | DYLD monitor | N/A |
| Emulator detection | 5-signal scoring | N/A | VM detection | N/A |
| Integrity verification | APK signature + DEX hash | Code signing + FairPlay | Code signing | N/A |
| DRM integration | Widevine | FairPlay | FairPlay | EME API |
| Certificate pinning | OkHttp SPKI | URLSession | URLSession | Browser-level |
| Secure media playback | ExoPlayer + SurfaceTexture | AVPlayer + CVPixelBuffer | AVPlayer + Timer | HTML5 Video |
| PDF rendering | PdfRenderer API | PDFKit | PDFKit | Browser viewer |

---

## Quick Start

### Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  cyber_guard:
    path: ../cyber_guard  # or your package path
```

### Initialize

```dart
import 'package:cyber_guard/cyber_guard.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await CyberGuard.initialize(
    config: SecurityConfig.maximum.copyWith(
      watermarkUserIdentifier: 'user@example.com',
      watermarkDisplayName: 'John Doe',
    ),
  );

  runApp(const MyApp());
}
```

### Protect Any Widget

```dart
CyberGuard.protect(
  child: MyConfidentialContent(),
)
```

This wraps your widget with the full protection stack — secure flags, watermark overlay, blur shield, and screen capture detection — all activated automatically.

### Protected Video Player

```dart
CyberGuard.videoPlayer(
  source: MediaSource.network(
    'https://example.com/protected-video.mp4',
  ),
  config: PlayerConfig(
    autoPlay: true,
    watermarkText: 'Confidential',
  ),
)
```

Supports MP4, WebM, MKV, HLS, DASH, RTMP, and audio formats (MP3, AAC, OGG). The player renders through a secure texture pipeline — content never touches unprotected memory.

### Protected PDF Viewer

```dart
CyberGuard.pdfViewer(
  source: PdfSource.network('https://example.com/document.pdf'),
  config: PdfViewerConfig(
    enableSearch: true,
    enableThumbnails: true,
    nightMode: false,
  ),
)
```

Native PDF rendering via platform APIs (PdfRenderer on Android, PDFKit on iOS/macOS). Pages are rendered as RGBA pixel data and displayed through the secure pipeline — no intermediate file caching.

### Protected Image Viewer

```dart
CyberGuard.imageViewer(
  sources: [
    ImageSource.network('https://example.com/image1.jpg'),
    ImageSource.network('https://example.com/image2.jpg'),
    ImageSource.asset('assets/confidential.png'),
  ],
  config: ImageViewerConfig(
    enableZoom: true,
    maxZoomScale: 5.0,
    showThumbnails: true,
  ),
)
```

Supports pinch-to-zoom (up to 5x), double-tap zoom, swipe navigation, Hero transitions, and LRU memory caching. All images are watermarked and blur-protected.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     FLUTTER UI LAYER (Dart)                      │
│  SecureContentWidget │ WatermarkOverlay │ BlurShield │ Viewers   │
├──────────────────────────────────────────────────────────────────┤
│                   PLATFORM CHANNEL BRIDGE                        │
│            MethodChannel + EventChannel (Dart <-> Native)        │
├────────────┬────────────┬─────────────┬──────────────────────────┤
│  ANDROID   │    iOS     │   macOS     │         WEB              │
│  Kotlin    │   Swift    │   Swift     │   JavaScript             │
│  C++ (JNI) │  Obj-C++   │   AppKit    │   Service Worker         │
│  Rust(FFI) │  Rust(FFI) │  Rust(FFI)  │   Rust(WASM)             │
├────────────┴────────────┴─────────────┴──────────────────────────┤
│                    RUST CORE ENGINE (FFI)                         │
│  Steganographic Watermark │ AES-256-GCM │ Process Detection      │
└──────────────────────────────────────────────────────────────────┘
```

### Project Structure

```
lib/
├── cyber_guard.dart                 # Public API barrel export
├── main.dart                        # App entry point
├── app.dart                         # Root widget with security state
│
├── api/                             # Developer-facing API
│   ├── cyber_guard_api.dart         # Primary facade (CyberGuard class)
│   ├── secure_media_player.dart     # Protected video/audio player
│   ├── secure_pdf_viewer.dart       # Protected PDF viewer
│   ├── secure_image_viewer.dart     # Protected image viewer/gallery
│   └── models/
│       ├── media_source.dart        # MediaSource, PdfSource, ImageSource
│       └── player_config.dart       # PlayerConfig, PdfViewerConfig, ImageViewerConfig
│
├── core/
│   ├── security/
│   │   ├── security_config.dart     # 30+ toggleable security parameters
│   │   ├── security_channel.dart    # Platform channel bridge (singleton)
│   │   ├── security_state.dart      # Immutable runtime state snapshot
│   │   ├── security_event.dart      # 18 typed security events
│   │   ├── rasp_engine.dart         # Threat scoring + response escalation
│   │   ├── certificate_pinner.dart  # SPKI SHA-256 TLS pinning
│   │   └── url_copy_guard.dart      # Clipboard leakage prevention
│   ├── encryption/
│   │   ├── content_encryptor.dart   # AES-256-GCM with memory zeroing
│   │   ├── secure_key_storage.dart  # Hardware-backed key storage
│   │   └── drm_bridge.dart          # Widevine / FairPlay / EME
│   ├── logging/
│   │   └── audit_logger.dart        # Hash-chained forensic audit trail
│   └── ffi/
│       └── native_bridge.dart       # Dart FFI bindings to Rust
│
├── media/                           # Media playback engine
│   ├── player_state.dart            # Immutable player state model
│   ├── secure_player_controller.dart
│   ├── player_controls.dart         # Interactive player UI
│   └── player_overlay.dart          # Buffering/error/completion states
│
├── viewers/                         # Document & image renderers
│   ├── pdf/
│   │   ├── pdf_controller.dart      # Page navigation + caching
│   │   ├── pdf_page_renderer.dart   # RGBA pixel rendering
│   │   └── pdf_thumbnail_strip.dart # Thumbnail navigation
│   └── image/
│       └── cached_secure_image.dart # LRU network image cache
│
├── ui/                              # Security UI widgets
│   ├── secure_content_widget.dart   # Full protection stack wrapper
│   ├── watermark_overlay.dart       # Rotated text grid overlay
│   ├── blur_shield.dart             # Threat-activated gaussian blur
│   └── security_status_bar.dart     # Shield status indicator
│
├── platform/                        # Platform abstraction
│   ├── platform_security.dart       # Capability detection
│   ├── web_security_bridge.dart     # Web security interface
│   ├── web_security_bridge_web.dart # JS interop implementation
│   └── web_security_bridge_stub.dart
│
└── demo/                            # Demo application
    ├── theme/app_theme.dart
    ├── widgets/                     # Glassmorphic UI components
    └── screens/                     # Splash, home, viewers, dashboard
```

---

## RASP Engine (Runtime Application Self-Protection)

The RASP engine operates as an autonomous security orchestrator. It continuously monitors all 10 defense layers, aggregates threat signals into a cumulative score, and escalates response automatically:

| Threat Level | Score | Color | Response |
|-------------|-------|-------|----------|
| Green | 0 | Safe | Normal operation |
| Yellow | 1-3 | Caution | Log + increase monitoring frequency |
| Orange | 4-6 | Warning | Blur content + alert |
| Red | 7-9 | Danger | Wipe decrypted buffers + lock |
| Critical | 10+ | Severe | Emergency shutdown |

```dart
// Monitor threat level changes
CyberGuard.stateStream.listen((state) {
  if (state.hasActiveThreats) {
    print('Active threats: ${state.activeThreats}');
  }
});
```

---

## Security Configuration

Every protection layer can be individually configured:

```dart
SecurityConfig(
  // Screen protection
  enableScreenCaptureDetection: true,
  enableBlurOnCapture: true,
  blurSigma: 20.0,

  // Watermark
  enableWatermark: true,
  watermarkOpacity: 0.08,
  watermarkUserIdentifier: 'user@example.com',
  watermarkDisplayName: 'John Doe',

  // Device integrity
  enableRootDetection: true,
  enableEmulatorDetection: true,
  enableAntiDebugging: true,
  enableHookDetection: true,
  enableIntegrityVerification: true,

  // Advanced
  enableCertificatePinning: true,
  enableClipboardGuard: true,
  enableRasp: true,
  monitoringIntervalMs: 1000,
  terminateOnCriticalThreat: false,
)
```

Or use the built-in preset:

```dart
SecurityConfig.maximum  // All layers enabled, strictest settings
```

---

## Encryption & Key Management

Content encryption uses AES-256-GCM with hardware-backed key storage:

```dart
// Generate and store a key securely
final key = ContentEncryptor.generateKey();
await CyberGuard.storeKey('content_key_1', key);

// Encrypt content
final encrypted = ContentEncryptor.encryptContent(
  plaintext: sensitiveData,
  key: key,
);

// Decrypt (with automatic memory zeroing after use)
final decrypted = ContentEncryptor.decryptContent(
  ciphertext: encrypted,
  key: key,
);
```

Keys are stored in:
- **Android**: Android Keystore (hardware TEE when available)
- **iOS/macOS**: Secure Enclave / Keychain
- **Web**: In-memory only (cleared on session end)

---

## Audit Trail

Every content viewing session is forensically logged with hash-chain integrity:

```dart
final log = await CyberGuard.getAuditLog();
for (final entry in log) {
  print('${entry.timestamp} — ${entry.userId} viewed ${entry.contentId}');
  print('Security state: ${entry.securityState}');
}
```

Each log entry is hash-chained to the previous one. Deleting or modifying any entry breaks the chain, making tampering detectable.

---

## Certificate Pinning

Prevent MITM attacks without third-party dependencies:

```dart
await CyberGuard.certificatePinner.pin(
  host: 'api.example.com',
  sha256Hashes: [
    'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    'backup-pin-hash-here',
  ],
);
```

Uses SPKI (Subject Public Key Info) SHA-256 hashing — the same approach used by Chrome and Firefox.

---

## Native Implementation Details

### Android
- **Security**: Kotlin + C++ (JNI) + Rust (FFI)
- **Media**: ExoPlayer via Media3 with SurfaceTexture rendering
- **PDF**: Android PdfRenderer API with ARGB-to-RGBA byte conversion
- **Detection**: Root (8 signals), Emulator (5-signal scoring), Hook (Frida/Xposed/Substrate), Memory integrity (APK signature + DEX hash + /proc/maps)

### iOS
- **Security**: Swift + Obj-C++ (ptrace, sysctl, IOKit)
- **Media**: AVPlayer with CVPixelBuffer via CADisplayLink
- **PDF**: PDFKit with CGContext RGBA rendering
- **Detection**: Jailbreak (7 signals), DYLD injection monitoring, IntegrityVerifier (code signing + FairPlay), Anti-debug (PT_DENY_ATTACH)

### macOS
- **Security**: Swift + AppKit
- **Window**: `NSWindow.sharingType = .none` prevents all screen sharing/recording
- **Media**: AVPlayer with Timer-based frame delivery
- **PDF**: PDFKit (shared implementation with iOS)
- **Detection**: SIP status, VM detection, DYLD monitoring, integrity verification

### Web
- **Canvas/WebGL**: Intercepts `toDataURL`, `getImageData`, `readPixels` to prevent pixel extraction
- **Screen sharing**: Blocks `getDisplayMedia` API
- **DevTools**: Three independent detection methods
- **Service Worker**: Injects CSP headers, X-Frame-Options, Permissions-Policy on all responses
- **UI**: Right-click, text selection, and drag prevention on protected content

---

## Demo Application

The project includes a built-in demo app with a glassmorphic dark UI showcasing all protection features:

- **Splash Screen** — Animated security initialization sequence
- **Protected Video Player** — Sample MP4 playback with watermark overlay
- **Protected PDF Viewer** — Document viewing with page navigation and search
- **Protected Image Gallery** — Grid with zoom, swipe, and Hero transitions
- **Security Dashboard** — Real-time threat gauge, defense status grid, and event timeline
- **Configuration Panel** — Live toggle switches for all security layers

Run the demo:

```bash
flutter run -d macos    # macOS
flutter run -d chrome   # Web
flutter run              # Connected device
```

---

## Build Verification

```bash
# Dart static analysis
flutter analyze

# Build targets
flutter build macos --debug
flutter build web
flutter build apk --debug
flutter build ios --debug --no-codesign
```

---

## Requirements

- Flutter SDK >= 3.10.3
- Dart SDK >= 3.10.3
- Xcode 15+ (iOS/macOS)
- Android SDK 24+ (Android)
- Rust toolchain (for FFI core engine)

## Dependencies

CyberGuard uses **zero third-party security packages**. The only dependencies are:

- `ffi` — Dart FFI for Rust interop
- `plugin_platform_interface` — Flutter platform channel contracts

Every security mechanism — encryption, watermarking, detection, audit logging, certificate pinning — is custom-built from scratch.

---

## License

This project is proprietary software. All rights reserved.
