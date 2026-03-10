# CyberGuard - Implementation Plan & Progress Tracker

> **Project:** Defense-in-Depth Content Protection Framework
> **Type:** Flutter Plugin (Android, iOS, macOS, Web)
> **Philosophy:** Zero third-party security packages. Everything custom-built.
> **Performance:** Rust via FFI for critical paths.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     FLUTTER UI LAYER (Dart)                      │
│  SecureContentWidget | WatermarkOverlay | BlurShield | BiometricGate │
├──────────────────────────────────────────────────────────────────┤
│                   PLATFORM CHANNEL BRIDGE                        │
│            MethodChannel + EventChannel (Dart <-> Native)        │
├────────────┬────────────┬─────────────┬─────────────────────────┤
│  ANDROID   │    iOS     │   macOS     │         WEB             │
│  Kotlin    │   Swift    │   Swift     │   JS + Dart (web)       │
│  C++ (JNI) │  Obj-C++   │   AppKit    │   WebGL + ServiceWorker │
│  Rust(FFI) │  Rust(FFI) │  Rust(FFI)  │   Rust(WASM)            │
├────────────┴────────────┴─────────────┴─────────────────────────┤
│                    RUST CORE ENGINE (FFI)                        │
│  Steganographic Watermark | AES-256-GCM | Process Detection     │
└──────────────────────────────────────────────────────────────────┘
```

## Security Layers (10 Independent Layers)

| # | Layer                    | What It Does                                      | Platform    |
|---|--------------------------|---------------------------------------------------|-------------|
| 1 | OS-Level Secure Flags    | FLAG_SECURE, UIScreen.isCaptured, NSWindow.sharingType | All native |
| 2 | Process Monitoring       | Scan for screenrecord, ffmpeg, obs, ReplayKit      | Android/iOS |
| 3 | GPU-Only Rendering       | Content in GPU memory only (CPU can't read pixels) | All        |
| 4 | Anti-Debug / Anti-Hook   | ptrace denial, Frida/Xposed/Substrate detection    | Android/iOS |
| 5 | Root/Jailbreak Detection | Multi-signal detection, blur content if detected   | Android/iOS |
| 6 | Visible Watermark        | Gmail/name/timestamp overlay on content            | All        |
| 7 | Steganographic Watermark | Invisible forensic ID embedded in pixel data       | All        |
| 8 | Content Encryption       | AES-256-GCM via HSM/Secure Enclave/TEE             | All        |
| 9 | Web Protections          | Service Worker, Canvas intercept, DevTools detect  | Web        |
| 10| Download/Copy Prevention | DRM flags, stream-only, no caching, link blocking  | All        |

---

## Target File Structure

```
cyber_guard/
├── rust/                              # Rust FFI Core Engine
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                     # FFI exports
│       ├── watermark.rs               # Steganographic engine
│       ├── crypto.rs                  # AES-256-GCM encryption
│       └── detection.rs              # Process/hook detection
│
├── android/
│   └── app/src/main/
│       ├── cpp/                       # C++ Native (JNI → Rust bridge)
│       │   ├── CMakeLists.txt
│       │   ├── security_core.cpp      # Main JNI entry points
│       │   ├── framebuffer_monitor.cpp
│       │   ├── anti_hook.cpp
│       │   └── rust_bridge.cpp        # C++ → Rust FFI bridge
│       ├── kotlin/com/cyberguard/
│       │   ├── CyberGuardPlugin.kt    # Flutter plugin entry
│       │   ├── SecurityBridge.kt      # JNI bridge class
│       │   ├── SecureActivity.kt      # Secure window management
│       │   ├── ScreenCaptureDetector.kt
│       │   ├── RootDetector.kt
│       │   ├── HypervisorDetector.kt
│       │   └── MemoryProtection.kt
│       └── AndroidManifest.xml
│
├── ios/
│   └── Runner/
│       ├── Security/
│       │   ├── CyberGuardPlugin.swift # Flutter plugin entry
│       │   ├── KernelSecurity.swift   # IOKit, sysctl monitoring
│       │   ├── ScreenCaptureDetector.swift
│       │   ├── HardwareProtection.swift # Metal GPU rendering
│       │   ├── JailbreakDetector.swift
│       │   └── MemoryEncryption.swift
│       └── SecurityBridge/
│           ├── KernelBridge.h
│           ├── KernelBridge.mm        # Obj-C++ low-level APIs
│           └── SecurityInterop.cpp
│
├── macos/
│   └── Runner/
│       ├── Security/                  # Shared logic with iOS
│       │   ├── CyberGuardPlugin.swift
│       │   ├── ScreenCaptureDetector.swift
│       │   └── HardwareProtection.swift
│       └── MainFlutterWindow.swift    # NSWindow secure config
│
├── web/
│   ├── security_sw.js                 # Service Worker
│   ├── shaders/
│   │   ├── watermark_fragment.glsl
│   │   └── secure_render.vert
│   └── index.html                     # CSP headers
│
├── lib/                               # Flutter/Dart Layer
│   ├── main.dart                      # Entry point
│   ├── app.dart                       # Root app widget
│   ├── core/
│   │   ├── security/
│   │   │   ├── security_channel.dart  # Platform channel bridge
│   │   │   ├── security_event.dart    # Event types & models
│   │   │   ├── security_config.dart   # Protection policy config
│   │   │   └── security_state.dart    # Runtime security state
│   │   ├── rendering/
│   │   │   ├── secure_widget.dart     # Main protection wrapper
│   │   │   ├── watermark_painter.dart # Custom painter for watermark
│   │   │   ├── blur_shield.dart       # Blur overlay on breach
│   │   │   └── gpu_protected_view.dart
│   │   └── encryption/
│   │       ├── content_encryptor.dart # Dart-side encryption API
│   │       └── secure_storage.dart    # Secure key/value storage
│   ├── features/
│   │   ├── viewer/
│   │   │   ├── secure_viewer_screen.dart
│   │   │   ├── video_player_secure.dart
│   │   │   ├── image_viewer_secure.dart
│   │   │   └── document_renderer.dart
│   │   └── auth/
│   │       └── biometric_gate.dart
│   └── platform/
│       ├── platform_security.dart     # Platform detection & dispatch
│       └── web_security_stub.dart     # Conditional web import
│
├── test/                              # Unit & integration tests
├── pubspec.yaml
├── analysis_options.yaml
├── implementation_plan.md             # This file
├── Cybar_Guard.md                     # Specification
└── Code.md                           # Reference code
```

---

# PHASE 1: PROJECT FOUNDATION & STRUCTURE

## What We Build
- Clean folder structure under `lib/`
- Core Dart models: SecurityEvent, SecurityConfig, SecurityState
- Platform channel contract (Dart side only)
- Updated `pubspec.yaml` with `ffi` support
- Root `app.dart` with security initialization flow
- Strict `analysis_options.yaml`

## What You Learn
- **Platform Channels:** How Flutter talks to native code. MethodChannel sends one-off requests (like "enable secure mode"). EventChannel streams continuous events (like "capture detected").
- **Security Event Model:** Every security incident is a typed event with timestamp and metadata. This lets us react uniformly regardless of which platform or layer detected the threat.
- **Singleton Pattern:** SecurityChannel is a singleton because there must be exactly ONE bridge to native code — multiple instances would cause duplicate event handling.

## Key Decisions
- Channel name: `com.cyberguard.security/bridge` (method), `com.cyberguard.security/events` (stream)
- Zero external dependencies for security (only `flutter`, `ffi`, `plugin_platform_interface`)
- Strict null safety, strict analysis rules

## Files Created
```
lib/
├── main.dart                    (rewritten)
├── app.dart                     (new)
├── core/
│   ├── security/
│   │   ├── security_channel.dart
│   │   ├── security_event.dart
│   │   ├── security_config.dart
│   │   └── security_state.dart
│   ├── rendering/               (empty, placeholder)
│   └── encryption/              (empty, placeholder)
├── features/                    (empty, placeholder)
└── platform/
    └── platform_security.dart
```

## Review Checklist
- [ ] All files compile (`dart analyze`)
- [ ] No third-party security packages in pubspec.yaml
- [ ] Platform channel names are consistent
- [ ] SecurityEvent enum covers all threat types
- [ ] SecurityConfig is immutable and serializable
- [ ] Singleton SecurityChannel has clean init/dispose lifecycle

---

# PHASE 2: ANDROID NATIVE FOUNDATION

## What We Build
- `CyberGuardPlugin.kt` — Flutter plugin registration
- `SecurityBridge.kt` — JNI bridge to C++ native code
- `SecureActivity.kt` — FLAG_SECURE, secure surface, window protection
- `ScreenCaptureDetector.kt` — MediaProjection callback detection
- C++ `security_core.cpp` — JNI entry points
- `CMakeLists.txt` — NDK build configuration
- Updated `build.gradle` — CMake integration

## What You Learn
- **FLAG_SECURE:** Android's built-in window flag that tells the compositor to treat the window as secure. Screenshots/recordings show a black screen. This is Layer 1 — necessary but insufficient (can be bypassed on rooted devices).
- **MediaProjection API:** Android's official screen recording API. We register a callback to detect when any app starts a MediaProjection session, then immediately blur content.
- **JNI (Java Native Interface):** How Kotlin/Java code calls C/C++ functions. We define `external fun` in Kotlin, implement the C function with matching JNI signature. This gives us access to Linux syscalls, /proc filesystem, and direct hardware.
- **Why C++ on Android:** Kotlin runs in the ART virtual machine which can be hooked (Xposed, Frida). C++ native code runs directly on the CPU — much harder to intercept.

## Key Decisions
- Package: `com.cyberguard.security`
- Native library name: `security_core`
- Min SDK: 24 (Android 7.0) for MediaProjection callback support
- C++ flags: `-O3 -fvisibility=hidden` (optimize + hide symbols)

## Review Checklist
- [ ] Plugin registers correctly with Flutter engine
- [ ] FLAG_SECURE applies on activity creation
- [ ] JNI functions have correct signatures
- [ ] CMake builds without errors
- [ ] MediaProjection detection fires events back to Dart

---

# PHASE 3: iOS/macOS NATIVE FOUNDATION

## What We Build
- `CyberGuardPlugin.swift` — Flutter plugin registration (iOS + macOS)
- `ScreenCaptureDetector.swift` — UIScreen.isCaptured + Darwin notifications
- `HardwareProtection.swift` — Metal GPU-only texture setup
- `KernelBridge.mm` — Obj-C++ for ptrace, sysctl, IOKit
- macOS: `MainFlutterWindow.swift` — NSWindow.sharingType = .none
- `AppDelegate.swift` — Security init before Flutter engine starts

## What You Learn
- **UIScreen.isCaptured:** iOS 11+ property that returns `true` when screen is being recorded, AirPlayed, or mirrored. We observe `capturedDidChangeNotification` for real-time detection.
- **Metal GPU Textures:** By creating textures with `.storageMode = .private`, the data lives ONLY in GPU memory. CPU (and therefore screenshots) cannot read it.
- **PT_DENY_ATTACH:** A ptrace request that prevents debuggers (LLDB, GDB) from attaching to the process. Called via dlsym to avoid static linking detection.
- **Darwin Notifications:** System-level notifications from SpringBoard (iOS's home screen manager). `com.apple.springboard.screencapture` fires when the user initiates a screenshot.
- **macOS sharingType:** `NSWindow.SharingType.none` prevents the window from being captured by screen sharing, screenshot tools, or recording software.

## Key Decisions
- Shared code between iOS and macOS where possible (ScreenCaptureDetector)
- Metal required (fallback to software rendering with full blur if no Metal)
- Anti-debug runs before Flutter engine initialization

## Review Checklist
- [x] Plugin registers on both iOS and macOS
- [x] UIScreen.isCaptured triggers event via EventChannel
- [ ] Metal texture created with .private storage (Phase 7)
- [x] PT_DENY_ATTACH called successfully (via dlsym, #if !DEBUG guard)
- [x] macOS window sharing disabled (NSWindow.sharingType = .none)
- [x] Events flow from Swift → Dart via EventChannel
- [x] App switcher blur protection (UIBlurEffect on iOS, NSVisualEffectView on macOS)
- [x] Darwin notification monitoring (iOS: springboard, macOS: screencapture.save)
- [x] Lifecycle observers for automatic blur on resign/become active
- [x] Explicit NotificationCenter cleanup in stopDetection
- [x] EventEmitter guards against closed stream before emitting
- [x] macOS ScreenCaptureDetectorMacOS for audit logging
- [x] Cleanup/deinit in all plugin classes

## Status: COMPLETE

---

# PHASE 4: RUST FFI CORE ENGINE

## What We Build
- `rust/Cargo.toml` — Workspace config with targets for all platforms
- `rust/src/lib.rs` — FFI C-compatible exports
- `rust/src/watermark.rs` — Steganographic watermark engine (LSB encoding)
- `rust/src/crypto.rs` — AES-256-GCM encryption/decryption
- `rust/src/detection.rs` — Cross-platform process/hook detection
- Build scripts for Android (cargo-ndk), iOS (cargo-lipo), WASM (wasm-pack)
- Dart FFI bindings via `dart:ffi`

## What You Learn
- **Why Rust:** Memory safety without garbage collection, zero-cost abstractions, and compiles to native machine code. Perfect for security-critical code that must be fast and un-tamperable.
- **Steganographic Watermarking (LSB):** We modify the Least Significant Bit of pixel color values to embed invisible data (user ID, timestamp, session ID). Invisible to the human eye but extractable from any photo of the screen.
- **AES-256-GCM:** Authenticated encryption — encrypts AND verifies integrity. If a single bit is tampered, decryption fails. We use this for content encryption.
- **dart:ffi:** Dart's Foreign Function Interface lets us call C-compatible functions from Dart. Rust exports `extern "C"` functions that Dart can call directly — no platform channel overhead.
- **Cross-compilation:** Rust compiles to `.so` (Android), `.a` (iOS), `.dylib` (macOS), `.wasm` (Web) from a single codebase.

## Key Decisions
- Rust edition 2021, minimal dependencies (only `aes-gcm`, `rand`)
- cbindgen generates C headers automatically
- Watermark encodes: user_id (32 bytes) + timestamp (8 bytes) + session_id (16 bytes)
- All FFI functions return error codes, never panic across FFI boundary

## Review Checklist
- [x] `cargo build` succeeds for host platform (macOS arm64 + x86_64)
- [x] 16/16 Rust unit tests pass (watermark, crypto, detection)
- [x] Watermark encode/decode roundtrip passes
- [x] Alpha channels untouched by watermark
- [x] LSB modification is minimal (max ±1 per channel)
- [x] AES-256-GCM encrypt/decrypt roundtrip passes
- [x] Wrong key returns DecryptionFailed (not crash)
- [x] Tampered data returns DecryptionFailed (auth tag verification)
- [x] Unique nonce per encryption (OsRng)
- [x] Dart FFI bindings with version compatibility check
- [x] No panics cross FFI boundary (catch_unwind on all extern "C")
- [x] Checked integer arithmetic for buffer size calculations
- [x] Detection uses word-boundary matching (avoids false positives)
- [x] C header generated via cbindgen
- [x] macOS .dylib linked and embedded in Flutter app
- [x] Build script regenerates headers automatically

## Status: COMPLETE

---

# PHASE 5: FLUTTER SECURITY UI LAYER

## What We Built
- `lib/ui/secure_content_widget.dart` — Wraps any child with full protection stack (lifecycle + watermark + blur)
- `lib/ui/watermark_overlay.dart` — CustomPainter that renders gmail/name/timestamp diagonally at 0.08 opacity
- `lib/ui/blur_shield.dart` — Animated BackdropFilter blur triggered on security events (40ms activation)
- `lib/ui/security_status_bar.dart` — Real-time threat indicator (compact + expandable modes)
- `lib/features/viewer/secure_viewer_screen.dart` — Full-screen viewer with all protections + demo screen
- `lib/app.dart` — Updated to use SecureViewerDemo as home screen (replaced _PlaceholderHome)

## What You Learned
- **CustomPainter Watermark:** Flutter's CustomPainter draws semi-transparent text (user email, name, timestamp) in a rotated (-30°) repeating grid across the content surface. Uses `IgnorePointer` so touches pass through, `RepaintBoundary` to isolate repaints, and `listEquals` for efficient `shouldRepaint`. The diagonal rotation and grid pattern prevent easy cropping or removal.
- **BackdropFilter Blur:** `BackdropFilter` with `ImageFilter.blur` applies GPU-accelerated Gaussian blur to everything behind it in the paint order. The `BlurShield` widget uses `AnimationController` with 40ms forward duration (< 50ms requirement). At 60fps, one frame = 16.6ms, so blur is fully applied within 2-3 frames. The blur also adds a semi-transparent dark overlay that scales with blur intensity.
- **Widget Lifecycle Security:** `SecureContentWidget` calls `enterSecureMode()` in `initState` and `exitSecureMode()` in `dispose`. A `_secureModeEntered` guard prevents double-enter/exit. The widget subscribes to `SecurityChannel.stateStream` and syncs with `currentState` on mount (in case events arrived before subscription).
- **Protection Stack Order:** The Stack layers are: [child, watermark, blur]. Blur is on TOP of watermark, so when blur activates, even the watermark becomes unreadable — preventing attackers from reading the user-identifying watermark text in a capture.

## Key Decisions
- Watermark opacity: 0.08 (barely visible but appears in captures)
- Blur sigma: 30.0 (content completely unreadable)
- Blur activation: 40ms forward, 200ms reverse (fast threat response, smooth clear)
- SecurityStatusBar: compact mode (icon only) for app bar, full mode (expandable details) for body
- BiometricGate and GpuProtectedView deferred to Phase 7 (requires native platform view integration)

## Review Checklist
- [x] Watermark renders correctly with user info (CustomPainter with rotated grid)
- [x] Blur activates within 50ms of security event (40ms AnimationController)
- [x] SecureContentWidget lifecycle is clean (no leaks, guard on enter/exit)
- [x] shouldRepaint uses listEquals for content equality (not reference equality)
- [x] Flutter analyzer: 0 issues across all Phase 5 files
- [x] macOS debug build passes

## Status: COMPLETE

---

# PHASE 6: ADVANCED ANDROID SECURITY

## What We Built
- `android/.../cpp/anti_hook.cpp` — C++ native Frida/Xposed/Substrate detection (4 methods: maps scan, port scan, thread scan, inline hook detection)
- `android/.../RootDetector.kt` — 7-signal root detection (su paths, Magisk, SuperSU, KernelSU, build tags, SELinux, root packages) + native signals
- `android/.../EmulatorDetector.kt` — Scoring-based emulator detection (build props, hardware, files, sensors, telephony; threshold=3)
- `android/.../MemoryProtection.kt` — APK/DEX integrity (SHA-256 hash), library count monitoring, injection scan, signature verification
- Updated `SecurityBridge.kt` — Added `nativeDetectHooks(): Int` and `nativeDetectRoot(): Int` (bitmask returns)
- Updated `SecurityMonitor.kt` — Fast checks every iteration (capture, debugger, hooks), slow checks every 10th (root, emulator, integrity)
- Updated `CyberGuardPlugin.kt` — Creates all detectors in handleInitialize, real results in handleGetDeviceIntegrity
- Updated `CMakeLists.txt` — Added anti_hook.cpp to build

## What You Learned
- **Root Detection (Multi-Signal):** No single root check is reliable. Magisk DenyList hides from individual checks. By combining 7 Kotlin signals + 2 native C++ signals (su binary via access(), Magisk mount traces), we make hiding root extremely difficult. Any single positive signal → blur all content.
- **Frida Detection (4 layers):** (1) Scan /proc/self/maps for injected library names (frida-agent, xposedbridge, substrate). (2) Try connecting to localhost:27042-27052 (Frida's default port). (3) Scan /proc/self/task/*/comm for Frida's GLib threads (gmain, gdbus, gum-js-loop) — require 2+ matches to avoid false positives. (4) Read first instruction of libc functions (open, read, connect) and check for ARM64 LDR+BR trampoline pattern (0x58xxxxxx) indicating inline hooks.
- **Inline Hook Detection Architecture:** On ARM64, a normal function starts with STP X29,X30,[SP,#-0x10]! but a hooked function starts with LDR X16,[PC,#8] + BR X16 (load absolute address, branch). On x86_64, hooks start with JMP (0xE9). We check 5 critical libc functions that our own detection code uses — if these are hooked, the attacker is trying to hide from our /proc scanning.
- **Emulator Scoring System:** Simple boolean detection causes false positives on cheap devices with generic build strings. Instead, each signal adds points: build props (0-5), hardware (0-3), files (0/2), sensors (0/1), telephony (0/1). Threshold of 3+ = definitely emulator. This eliminates false positives while catching all major emulators (Android Studio, Genymotion, NOX, BlueStacks, VirtualBox).
- **Memory Integrity Baseline:** On first run, compute SHA-256 of classes.dex and store it. On each subsequent check, recompute and compare. Also count loaded .so libraries — if count increases by >5 from baseline, injection is suspected. Monitor /proc/self/maps for known injection signatures.
- **Check Frequency Strategy:** Fast checks (capture, debugger, hooks) run every monitoring iteration (~100ms) because these threats can appear at any moment and the checks are cheap /proc reads. Slow checks (root, emulator, integrity) run every 10th iteration (~1s) because they're expensive (file I/O, package manager, crypto) and these states don't change at runtime.
- **Case-Sensitivity Bug Found & Fixed:** Hook signatures must be ALL LOWERCASE since we convert /proc/self/maps lines to lowercase before comparing. Original had "XposedBridge" and "SubstrateHook" which would never match — fixed to "xposedbridge" and "substratehook".

## Key Decisions
- Native hook detection returns bitmask (not bool) so Kotlin knows WHICH method triggered — important for forensic logging
- Root detection requires ANY single positive signal (not multiple) — security-critical, false negatives are worse than false positives
- Emulator detection requires score >= 3 — false positives (blocking real users) are worse than false negatives here
- MemoryProtection stores baseline in SharedPreferences — persists across app restarts
- Frida thread scan requires 2+ matching threads (a single "gmain" could be legitimate)

## Review Checklist
- [x] Root detection catches: Magisk (files + package + native mounts), SuperSU (files + package), KernelSU (files + package)
- [x] Frida detection: server mode (port scan), gadget mode (maps scan), agent mode (thread scan + inline hooks)
- [x] Inline hook detection covers ARM64 (LDR+BR), ARM32 (LDR PC), and x86/x64 (JMP/INT3)
- [x] Content blurs on compromised device (events flow through SecurityMonitor → EventEmitter → Dart SecurityState → BlurShield)
- [x] False positive avoidance: emulator uses scoring threshold, Frida threads require 2+ matches, root uses file existence (not executable check)
- [x] Hook signatures are ALL LOWERCASE (fixed case-sensitivity bug)
- [x] macOS debug build passes (Dart code compiles clean)

## Status: COMPLETE

---

# PHASE 7: ADVANCED APPLE SECURITY ✅

## What We Built
- `JailbreakDetector.swift` — 7-signal jailbreak detection (files, URLs, sandbox escape, fork, dylibs, symlinks, env vars)
- `DYLDMonitor.swift` — Shared iOS/macOS dyld library injection detection with baseline tracking
- `IntegrityVerifier.swift` — Code signing (macOS SecStaticCode), executable hash (SHA-256 baseline), FairPlay encryption check (iOS)
- Updated `CyberGuardPlugin.swift` (iOS) — Wired all Phase 7 detectors + simulator detection
- Updated `CyberGuardPluginMacOS.swift` — Wired DYLD + integrity + SIP disabled check + VM detection
- `handleGetDeviceIntegrity` now returns real detection results on both iOS and macOS (was hardcoded false)

## What You Learned

### Jailbreak Detection (iOS — 7 Signals)
- **File path checks (20+ paths):** Each jailbreak leaves different artifacts. checkra1n → `/var/checkra1n.dmg`, Taurine → `/.installed_taurine`, Dopamine → `/.installed_dopamine`, rootless jailbreaks → `/var/jb`. Also check for bypass tool bundles (Liberty, Shadow, A-Bypass) — their presence proves the device IS jailbroken.
- **URL scheme check:** `UIApplication.shared.canOpenURL()` returns true for `cydia://`, `sileo://`, `zbra://`, `filza://` only when those apps are installed.
- **Sandbox escape:** Try writing to `/private/var/tmp/` — should fail on stock iOS. Clean up test file if it succeeds.
- **fork() via dlsym:** Swift marks `fork()` as unavailable on iOS, but it exists in libSystem. Use `dlsym(RTLD_NOW, "fork")` + `unsafeBitCast` to call it. Same technique as ptrace in AntiDebugProtection. fork() should return -1 on non-jailbroken iOS.
- **Suspicious dylibs:** `_dyld_image_count()` + `_dyld_get_image_name(i)` enumerates all loaded libraries. Check for Frida, Cycript, Substrate, etc.
- **Symbolic links:** `/Applications` is a real directory on stock iOS. Some jailbreaks replace it with a symlink to `/var/stash/Applications`.
- **Environment vars:** `DYLD_INSERT_LIBRARIES`, `_MSSafeMode`, `SUBSTRATE_LIBRARY` — used by Substrate for dylib injection.

### DYLD Monitoring (Shared iOS/macOS)
- **Baseline approach:** Record `_dyld_image_count()` at init. Normal apps load all dylibs at launch. Growth of >5 after baseline suggests runtime injection.
- **Signature scanning:** 30+ known signatures covering Frida, Cycript, Substrate, Substitute, TweakInject, SSLKillSwitch, Reveal, Shadow, Liberty. ALL LOWERCASE — convert image paths to lowercase before matching (same lesson as Android anti_hook.cpp).
- **Shared code:** The dyld API (`_dyld_image_count`, `_dyld_get_image_name`) is identical on iOS and macOS — same source file works on both platforms.

### Integrity Verification
- **Code signing (macOS only):** `SecStaticCodeCreateWithPath` + `SecStaticCodeCheckValidity` with `kSecCSCheckAllArchitectures | kSecCSStrictValidate`. iOS doesn't expose `SecStaticCode` — the kernel enforces code signing via AMFI instead.
- **Executable hash:** `Bundle.main.executablePath` → read file → `CC_SHA256` → compare against UserDefaults baseline. Detects binary patches even if attacker re-signs.
- **FairPlay encryption (iOS only):** Walk Mach-O load commands to find `LC_ENCRYPTION_INFO_64`. `cryptid == 0` means the binary was dumped from memory (tools: dumpdecrypted, Clutch, frida-ios-dump). Guard with `#if !DEBUG` since dev builds aren't encrypted.
- **CFURLPathStyle gotcha:** Swift enum case is `.cfurlposixPathStyle` (lowercase), not `.cfURLPOSIXPathStyle`. Swift imports CF enums with different capitalization than the C names.

### macOS-Specific Detections
- **SIP (System Integrity Protection) check:** Read `kern.bootargs` via `sysctlbyname`. If it contains `amfi_get_out_of_my_way`, SIP is disabled — macOS equivalent of "rooted".
- **VM detection:** Read `hw.model` via `sysctlbyname`. Physical Macs return "MacBookPro18,1" etc. VMs return "VMware*", "Parallels*", "VirtualBox", "QEMU".

### iOS Simulator Detection
- **Compile-time:** `#if targetEnvironment(simulator)` is the most reliable check.
- **Runtime fallback:** Check for `SIMULATOR_DEVICE_NAME` environment variable (set by Xcode).

### Build Fixes
- **C++ comment bug:** `*/` inside file path `/proc/self/task/*/comm` in a `/* */` block comment prematurely closes the comment. The C preprocessor sees `*/comm` as end-of-comment + code. Fix: use `{tid}` placeholder instead of `*`.
- **fork() unavailable in Swift:** iOS SDK marks `fork()` as unavailable. Workaround: look up via `dlsym` and call through `unsafeBitCast` — same pattern as `ptrace` for anti-debug.

## Review Checklist
- [x] Jailbreak detection covers: checkra1n, unc0ver, Taurine, Dopamine (file artifacts for each)
- [x] DYLD monitoring detects Frida/Cycript/Substrate injection (30+ signatures)
- [x] Code signing verification uses SecStaticCode on macOS
- [x] Executable hash baseline stored and verified on both platforms
- [x] FairPlay encryption check on iOS (LC_ENCRYPTION_INFO_64 cryptid)
- [x] Simulator detection (iOS) and VM detection (macOS)
- [x] SIP disabled detection (macOS equivalent of root)
- [x] All three platforms build successfully (iOS, macOS, Android)

---

# PHASE 8: WEB SECURITY LAYER ✅

## What We Built
- `web/security_guard.js` — Main JS security engine (6 protection layers)
- `web/security_sw.js` — Service Worker for CSP headers + request interception
- `lib/platform/web_security_bridge.dart` — Abstract bridge interface
- `lib/platform/web_security_bridge_stub.dart` — No-op stub for native platforms
- `lib/platform/web_security_bridge_web.dart` — Real implementation via `dart:js_interop`
- Updated `lib/core/security/security_channel.dart` — Web bridge integration with kIsWeb dispatch
- Updated `web/index.html` — Loads security_guard.js synchronously before Flutter

## What You Learned

### Why Web is the Hardest Platform
- Users have **full control** of the browser. Can't prevent OS-level screenshots (PrtScn, Snipping Tool).
- JavaScript can be disabled entirely (but then the app won't work either).
- Browser extensions can override our overrides (arms race).
- Strategy: make casual capture difficult, make programmatic capture fail, detect inspection tools, and ensure forensic watermarks survive in any leaked content.

### Canvas/WebGL Readback Prevention (Layer 1)
- **Prototype chain override:** `HTMLCanvasElement.prototype.toDataURL` is the function ALL canvases share. Replacing it affects every canvas on the page, including Flutter's CanvasKit render canvas.
- **toDataURL override:** Returns a 1x1 transparent PNG instead of actual content. Browser extensions calling `canvas.toDataURL()` get blank data.
- **toBlob override:** Creates a temp 1x1 canvas and calls original `toBlob` on that.
- **getImageData override (2D):** Returns `new ImageData(w, h)` — all zeros (transparent black).
- **readPixels override (WebGL/WebGL2):** Leaves the pixels array untouched (all zeros by default). This blocks WebGL-based capture tools.
- **Limitation:** Does NOT prevent OS-level screenshots — those capture the composited framebuffer from the GPU, which JavaScript cannot intercept.

### Screen Sharing Block (Layer 2)
- **`navigator.mediaDevices.getDisplayMedia`** is the browser API for screen sharing (Zoom, Meet, etc.) and screen recording extensions.
- Override returns `Promise.reject(new DOMException(..., "NotAllowedError"))` — indistinguishable from the user clicking "Deny" on the permission prompt.

### DevTools Detection (Layer 3 — 3 Independent Methods)
- **Method 1: Window size differential.** Docked DevTools shrinks `innerWidth`/`innerHeight` while `outerWidth`/`outerHeight` stay the same. Threshold >160px indicates DevTools. Misses undocked (separate window) DevTools.
- **Method 2: Console trap.** Create an `Image()` object with a getter on its `id` property. Pass to `console.log()`. Chrome evaluates the getter ONLY when DevTools Console tab is open — gives reliable detection of the Console panel.
- **Method 3: Debugger timing.** The `debugger` statement takes ~0ms without DevTools but >100ms with DevTools open (UI pauses). Used sparingly (every 5th check) due to jank. Disabled by default.
- State change detection: only emit event on transition (open→closed or closed→open), not every poll.

### Keyboard Shortcut Interception (Layer 4)
- `addEventListener("keydown", handler, { capture: true })` — capture phase fires BEFORE any other handlers.
- `preventDefault()` + `stopPropagation()` consumes the event completely.
- Blocked: PrintScreen, F12, Ctrl+S, Ctrl+P, Ctrl+U, Ctrl+Shift+I/J/C/S.
- Cannot block OS-level shortcuts (Win+PrtScn, macOS Cmd+Shift+3/4).

### Interaction Protection (Layer 5)
- Context menu (right-click): blocked via `contextmenu` event — prevents "Save Image As", "Copy Image", "Inspect Element".
- Text selection: blocked via `selectstart` event.
- Drag: blocked via `dragstart` event — prevents dragging images/text to desktop.

### CSS Injection (Layer 6)
- `user-select: none`, `-webkit-user-drag: none`, `-webkit-touch-callout: none` on `body.cyberguard-secure`.
- `@media print` rule: hides all content (`visibility: hidden`) and shows "Protected content — printing is not permitted" message.
- Toggled by adding/removing `cyberguard-secure` class on `<body>`.

### Service Worker (security_sw.js)
- **Lifecycle:** `install` → `skipWaiting()` (activate immediately), `activate` → `clients.claim()` (control all tabs).
- **Fetch interception:** Only intercepts same-origin requests (cross-origin passes through).
- **Security headers added to every response:**
  - `Content-Security-Policy`: `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'` (blocks iframes, Flash). `unsafe-inline`/`unsafe-eval` needed for Flutter CanvasKit.
  - `X-Frame-Options: DENY` (legacy clickjacking protection).
  - `X-Content-Type-Options: nosniff` (prevents MIME sniffing attacks).
  - `Referrer-Policy: strict-origin-when-cross-origin` (prevents URL leakage).
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), display-capture=()` (restricts browser APIs).

### Dart Web Bridge — Conditional Import Pattern
- **Problem:** `dart:js_interop` only exists on web. Importing it unconditionally breaks native builds.
- **Solution:** Conditional import: `import 'stub.dart' if (dart.library.js_interop) 'web.dart';`
- At compile time: web → imports `web_security_bridge_web.dart` (uses `dart:js_interop`); native → imports `web_security_bridge_stub.dart` (no-ops).
- Both files export `createPlatformBridge()` with the same signature.
- **JS interop API:** Use `@JS()` annotation + `external` for function bindings. Use extension types (`extension type _JSStatusResult(JSObject _)`) for typed property access. Use `Reflect.set()` for setting properties on plain JS objects.

### SecurityChannel Web Integration
- `kIsWeb` check in `initialize()`, `enterSecureMode()`, `exitSecureMode()`, `getDeviceIntegrity()`.
- Web path: calls `_webBridge` methods directly (no MethodChannel).
- Native path: unchanged MethodChannel flow.
- Web events: `_webBridge.setEventCallback()` → `_handleWebEvent()` → `_processEvent()` — same event pipeline as native.
- `getDeviceIntegrity()` on web: returns `isDebugger: status['isDevToolsOpen']`. Root/emulator/hook don't apply to browsers.

### Build Note
- `security_guard.js` loaded synchronously (`<script src="...">` without `async`) BEFORE `flutter_bootstrap.js`. This ensures prototype overrides are in place before Flutter's CanvasKit can use the originals.

## Review Checklist
- [x] Service Worker registers and intercepts requests (CSP + 5 security headers)
- [x] Canvas toDataURL returns blank 1x1 PNG on protected content
- [x] getDisplayMedia is blocked (NotAllowedError)
- [x] DevTools detection via window size + console trap (2 active methods)
- [x] Keyboard shortcuts blocked (PrtScn, F12, Ctrl+S/P/U, Ctrl+Shift+I/J/C)
- [x] Right-click, text selection, drag blocked
- [x] Print blocked via @media print CSS
- [x] Conditional import pattern compiles on all 4 platforms
- [x] All 4 platforms build: web, iOS, macOS, Android

---

# PHASE 9: CONTENT PROTECTION & DRM ✅

## What We Built
- `lib/core/encryption/content_encryptor.dart` — High-level AES-256-GCM encryption/decryption wrapper with mandatory memory zeroing
- `lib/core/encryption/secure_key_storage.dart` — Platform-specific key storage (AndroidKeyStore, iOS/macOS Keychain, Web in-memory)
- `lib/core/encryption/drm_bridge.dart` — Widevine/FairPlay/EME DRM integration hooks via MethodChannel
- `lib/core/logging/audit_logger.dart` — Persistent audit trail with hash chain tamper detection (JSONL + ring buffer)
- `lib/core/security/url_copy_guard.dart` — Clipboard monitoring, auto-scrubbing, and copy prevention
- Updated `lib/core/security/security_config.dart` — Added Phase 9 toggles (encryption, audit, clipboard guard, DRM, license server URL)
- Updated `lib/core/security/security_event.dart` — Added 6 new event types (clipboardCopy, decryptionFailure, auditTampered, drmLicenseFailure, dyldInjection, sipDisabled)

## What You Learned

### Content Encryption Lifecycle
- **Zero-disk principle:** Content flows as: server → encrypted bytes → decrypt in memory → render to GPU → zero buffer. Unencrypted content must NEVER touch disk.
- **Chunk-based streaming:** Large files (video, PDF) are NOT decrypted all at once. Each chunk is independently encrypted with its own nonce. Decrypt one chunk → render → zero → next chunk. At most one unencrypted chunk exists in memory at any time.
- **Memory zeroing limitations:** `Uint8List.fillRange(0, length, 0)` zeros the known buffer, but Dart's generational GC may have already promoted copies to a different heap generation. We can't guarantee ALL copies are zeroed, but zeroing the known reference reduces the exposure window from "until GC" to "rendering duration only." Defense-in-depth — every bit helps.
- **NativeBridge uses positional params:** The Rust FFI bridge functions use positional parameters (`encrypt(key, plaintext)`) not named (`encrypt(key: key, plaintext: plaintext)`). Common mistake when wrapping FFI calls.

### Secure Key Storage Architecture
- **Why not SharedPreferences:** SharedPreferences stores data as plaintext XML/plist on disk. On a rooted/jailbroken device, any app can read it. Encryption keys stored there are trivially extractable.
- **Android KeyStore (TEE/StrongBox):** Keys are stored in hardware-backed storage. Even root access cannot extract key material — the hardware performs crypto operations without exposing the raw key. We store content keys encrypted by a KeyStore master key.
- **iOS/macOS Keychain (Secure Enclave):** The Keychain encrypts items with a key derived from the device passcode and hardware UID. Items can be marked as requiring biometric authentication to access.
- **Web: in-memory only:** Web has no secure persistent storage. Keys exist only in JavaScript memory for the session. When the tab closes, keys are gone — the server must re-issue keys each session.
- **MethodChannel for native access:** We use `com.cyberguard.security/keystore` to communicate with Android KeyStore wrapper (Kotlin) and iOS/macOS Keychain wrapper (Swift). Keys are base64-encoded for channel transport. `MissingPluginException` triggers fallback to in-memory storage.
- **Key zeroing on clearAll:** Before removing keys from the in-memory map, we zero every byte with `fillRange(0, length, 0)`. Prevents key material from lingering in the Dart heap.

### Audit Logging Design
- **Hash chain for tamper detection:** Each log entry includes the hash of the previous entry. If an attacker deletes or modifies an entry, the chain breaks — cryptographic proof of tampering. Uses FNV-1a hash (fast, non-cryptographic; for production use SHA-256).
- **JSONL format:** One JSON object per line. Easy to parse, append-friendly, and compatible with log analysis tools (grep, jq, Splunk). Daily file rotation: `audit_YYYYMMDD.jsonl`.
- **In-memory ring buffer:** 500-entry `Queue<AuditEntry>` serves as both the web-only storage and a recent-events cache on native platforms. Oldest entries are evicted when the buffer is full.
- **Who/What/When/Where/Security:** Every entry captures: sessionId (links start→end), userId, contentId, contentType, timestamp, viewDuration, deviceInfo (platform, model, app version), securityEventCount (threats during viewing), securityEventTypes (which specific threats occurred).
- **dart:io on web:** Initially removed `import 'dart:io'` which broke `File`/`Directory`/`FileMode` references. Fix: re-add the import — Flutter's web compiler stubs out `dart:io` classes, and all disk I/O is guarded by `if (!kIsWeb)` checks so the stubbed code never executes.
- **Documents path without path_provider:** Used a dedicated MethodChannel (`com.cyberguard.security/audit`) to get the documents directory path from native code, avoiding the `path_provider` dependency. Native side responds with platform-specific paths: `Context.getFilesDir()` (Android), `NSSearchPathForDirectoriesInDomains(.documentDirectory)` (iOS/macOS).

### DRM Integration Architecture
- **Widevine (Android):** L1 = hardware-backed decryption inside TEE (highest security, Netflix HD). L3 = software-only decryption (fallback for devices without TEE). Accessed via Android's `MediaDrm` API through MethodChannel.
- **FairPlay (iOS/macOS):** Uses `AVContentKeySession`. The device generates an SPC (Server Playback Context), sends it to the key server, and receives a CKC (Content Key Context). Keys are stored in Secure Enclave.
- **EME (Web):** W3C Encrypted Media Extensions — `requestMediaKeySystemAccess()` provides Widevine or FairPlay in-browser. Handled by the browser's built-in CDM (Content Decryption Module).
- **License lifecycle:** Create session → generate challenge (binary data) → app sends to license server → process response → key stored in hardware → content plays with hardware decryption → release session on exit.
- **DRM disabled by default:** Requires a license server, which is infrastructure the app developer must provide. The toggle `enableDrm` defaults to `false`.

### Clipboard Protection
- **Android < 12 vulnerability:** Any app can read the clipboard continuously. Malicious apps monitor for sensitive data (passwords, URLs, tokens). On Android 12+, the system shows a toast when an app reads the clipboard.
- **3-layer approach:** (1) Native clipboard monitoring via MethodChannel — detects clipboard changes and auto-clears after a delay. (2) Dart-level `Clipboard.setData(ClipboardData(text: ''))` for cross-platform clearing. (3) Periodic pattern matching — scrub clipboard every 5 seconds if it contains sensitive patterns (content IDs, auth tokens).
- **Auto-clear delay:** Default 30 seconds. Short enough to limit exposure, long enough for legitimate pastes. Configurable via `clipboardAutoClearDelayMs`.
- **Exit scrub:** When deactivating the guard (exiting secure mode), always clear the clipboard to ensure no protected content lingers.

### SecurityConfig Expansion
- 6 new fields added: `enableContentEncryption` (default: true), `enableAuditLogging` (default: true), `enableClipboardGuard` (default: true), `enableDrm` (default: false), `clipboardAutoClearDelayMs` (default: 30000), `drmLicenseServerUrl` (nullable).
- All new fields added to constructor, `toMap()`, and `copyWith()` — maintaining the immutable config pattern.
- `maximum` preset unchanged — it already enables all boolean flags via defaults.

### SecurityEvent Expansion
- 6 new event types: `clipboardCopy` (content copied in secure mode), `decryptionFailure` (wrong key, tampered data, auth tag mismatch), `auditTampered` (hash chain broken), `drmLicenseFailure` (license revoked or acquisition failed), `dyldInjection` (injected dylib detected), `sipDisabled` (macOS SIP disabled).

## Review Checklist
- [x] Content encryption wraps Rust FFI with mandatory memory zeroing
- [x] Chunk-based streaming decryption pattern documented and supported
- [x] Secure key storage uses hardware-backed stores on all native platforms
- [x] Audit logger uses hash chain for tamper detection
- [x] Audit entries capture who/what/when/where/security context
- [x] Clipboard guard monitors, scrubs, and auto-clears
- [x] DRM bridge supports Widevine, FairPlay, and EME via MethodChannel
- [x] SecurityConfig updated with all Phase 9 toggles
- [x] SecurityEventType extended with 6 new content protection events
- [x] All 4 platforms build: macOS, iOS, Android, Web
- [x] Flutter analyzer: 0 errors, 0 warnings

---

# PHASE 10: HARDENING & PRODUCTION ✅

## What We Built
- `lib/core/security/certificate_pinner.dart` — Custom TLS certificate pinning (SPKI SHA-256 pin verification)
- `lib/core/security/rasp_engine.dart` — RASP engine: threat scoring, autonomous escalation (green→yellow→orange→red→critical), self-check
- `lib/core/security/pentest_checklist.dart` — 28 attack vectors across 6 categories with expected defense behavior
- `android/app/proguard-rules.pro` — R8 obfuscation rules (JNI keep, Flutter plugin keep, aggressive repackaging)
- `android/app/build.gradle.kts` — Enabled `isMinifyEnabled` + `isShrinkResources` for release builds
- `test/security_test_suite.dart` — 39 tests covering all security layers (events, config, state, audit, RASP)
- Updated `security_config.dart` — Added `enableCertificatePinning`, `enableRasp`, `pinnedCertificates`
- Updated `security_event.dart` — Added `certificatePinFailure`, `raspTampered` event types

## What You Learned

### Certificate Pinning (SPKI SHA-256)
- **SPKI = Subject Public Key Info:** The DER-encoded public key from the certificate. We hash this with SHA-256 and base64-encode it. This is more stable than hashing the whole certificate because the public key stays the same when a certificate is renewed (if the same key pair is used).
- **Pin at least 2 hashes per host:** Current certificate + backup. If you only pin one and the certificate rotates, all clients break. The backup pin can be a key you've generated but not yet deployed — so you can rotate without app update.
- **Web limitation:** Browsers control the TLS stack. JavaScript cannot access the certificate chain during a connection. Certificate pinning is only possible on native platforms (Android OkHttp, iOS/macOS URLSession delegate).
- **Getting the pin hash:** `openssl s_client -connect host:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`
- **Unpinned hosts pass through:** If no pins are configured for a host, the connection proceeds normally. This prevents breaking non-content-server connections.

### RASP (Runtime Application Self-Protection)
- **Threat scoring system:** Each security event type has a weight (0-6). Scores accumulate. Score thresholds: 0=green, 1-3=yellow, 4-6=orange, 7-9=red, 10+=critical. This prevents overreaction to benign signals (emulator=3 alone is orange) while ensuring combined attacks trigger aggressive defense (root+hooking=3+5=8 → red → wipe).
- **One-way escalation:** Threat levels only go UP, never down. An attacker could fake a "cleared" state to de-escalate. Once red, always red for the session.
- **Response escalation:** Green=normal, Yellow=clipboard guard, Orange=blur+notify, Red=wipe content+revoke keys, Critical=wipe+terminate.
- **Self-check loop:** Every 30 seconds, the RASP engine verifies: (1) SecurityChannel is still initialized (attacker might dispose it), (2) Event subscription is still active (attacker might cancel it), (3) Config integrity (terminateOnCritical not switched to false at runtime).
- **Orchestrator pattern:** RASP doesn't implement any detection itself — it subscribes to SecurityChannel.eventStream and coordinates responses across all other subsystems (AuditLogger, CertPinner, CopyGuard, KeyStorage, DrmBridge).

### R8/ProGuard Obfuscation
- **R8 is the default:** Since Android Gradle Plugin 3.4+, R8 replaced ProGuard but still reads proguard-rules.pro files. R8 does tree shaking (remove unused code), obfuscation (rename to a.b.c), and optimization (inlining, constant folding).
- **JNI keep rules are critical:** C++ native code calls Kotlin methods by exact JNI signature (`Java_com_myapp_cyber_1guard_SecurityBridge_onSecurityEvent`). If R8 renames the method, JNI lookups crash with `NoSuchMethodError`. Every `native fun` and every JNI callback must have a `-keep` rule.
- **Flutter plugin registration:** The Flutter engine finds plugins by class name. If R8 renames `CyberGuardPlugin`, the plugin silently fails to load. Keep the `onAttachedToEngine` and `registerWith` methods.
- **`-repackageclasses 'cg'`:** Moves all obfuscated classes into a flat package `cg.a`, `cg.b`, etc. Makes the class hierarchy impossible to reconstruct from a decompiled APK.
- **Log stripping:** `-assumenosideeffects class android.util.Log { d(...); v(...); i(...); }` tells R8 that these calls have no side effects, so they can be removed entirely in release builds. Prevents attackers from reading detection logic via `adb logcat`.
- **`isMinifyEnabled = true` + `isShrinkResources = true`:** Both must be set in the release buildType. `isMinifyEnabled` enables R8 code processing. `isShrinkResources` removes unused drawable/layout/string resources from the APK.

### Security Test Suite Design
- **What we CAN test in Dart:** Event deserialization roundtrips, config immutability, state machine transitions, audit log hash chain integrity, threat scoring math, enum coverage.
- **What we CAN'T test in Dart:** Real FLAG_SECURE behavior, actual root/jailbreak detection, Frida detection, GPU rendering, platform DRM. These require real devices and are covered by the pentest checklist.
- **Sticky threat flags:** A critical security invariant — once `isDeviceRooted` is true, it must NEVER auto-clear. An attacker could send a fake "rootCleared" event. The test verifies that applying other events doesn't clear existing threat flags.
- **Duplicate event deduplication:** Applying the same event type multiple times should NOT duplicate it in `activeThreats`. The test verifies `rootDetected` appears exactly once even after 3 applications.

### Penetration Testing Checklist
- **28 vectors across 6 categories:** Screen Capture (5), Anti-Debug (6), Device Integrity (7), Network (3), Content Protection (6), Watermark Resistance (3).
- **14 critical vectors:** These are the "must pass" tests — failure means content can be extracted or protections completely bypassed.
- **Platform-specific filtering:** `vectorsForPlatform(Platform.android)` returns only vectors relevant to Android (including `Platform.all`, `Platform.native`, `Platform.mobile`). Allows targeted testing per platform.

## Review Checklist
- [x] R8 obfuscation enabled with JNI/Flutter keep rules
- [x] Certificate pinning supports multi-pin per host (rotation-safe)
- [x] RASP threat scoring with 5-level escalation (green→critical)
- [x] RASP self-check detects tampering with security engine
- [x] 39/39 integration tests pass
- [x] 28 pentest vectors documented with expected defense behavior
- [x] SecurityConfig updated with Phase 10 toggles
- [x] SecurityEventType extended with 2 new hardening events
- [x] All 4 platforms build: macOS, iOS, Android, Web
- [x] Flutter analyzer: 0 errors, 0 warnings

---

# Phase 11: Reusable API Layer & Package Structure

> **Status:** COMPLETE
> **Goal:** Create a clean, developer-friendly API facade so any app can use CyberGuard with minimal code. Restructure as a proper plugin with separated demo.

## Architecture

```
┌──────────────────────────────────────────────────┐
│             CyberGuard (Public Facade)            │
│  ┌────────────────────────────────────────────┐  │
│  │ .initialize()  .protect()  .dispose()      │  │
│  │ .videoPlayer() .pdfViewer() .imageViewer() │  │
│  │ .fullScreenViewer() .securityDashboard()   │  │
│  └──────────────────┬─────────────────────────┘  │
│                     │                             │
│  ┌──────────────────┴─────────────────────────┐  │
│  │   SecurityChannel │ RaspEngine              │  │
│  │   ContentEncryptor │ AuditLogger            │  │
│  │   SecureKeyStorage │ CertificatePinner      │  │
│  │   SecureContentWidget │ WatermarkOverlay    │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/cyber_guard.dart` | Barrel export — single `import 'package:cyber_guard/cyber_guard.dart'` for consumers |
| 2 | `lib/api/cyber_guard_api.dart` | `CyberGuard` facade class — initialize, protect, dispose |
| 3 | `lib/api/secure_media_player.dart` | Public API stub for protected video/audio playback |
| 4 | `lib/api/secure_pdf_viewer.dart` | Public API stub for protected PDF viewing |
| 5 | `lib/api/secure_image_viewer.dart` | Public API stub for protected image viewing |
| 6 | `lib/api/models/media_source.dart` | `MediaSource` (network/asset/file), `PdfSource`, `ImageSource` |
| 7 | `lib/api/models/player_config.dart` | Player configuration (autoplay, loop, controls, etc.) |

## Usage Example

```dart
// 1. Initialize once at app startup
await CyberGuard.initialize(
  config: SecurityConfig.maximum.copyWith(
    watermarkUserIdentifier: user.email,
    watermarkDisplayName: user.name,
  ),
);

// 2. Protect any widget
CyberGuard.protect(child: MyWidget())

// 3. Play protected video
CyberGuard.videoPlayer(source: MediaSource.network('https://...'))

// 4. View protected PDF
CyberGuard.pdfViewer(source: PdfSource.network('https://...'))

// 5. View protected image gallery
CyberGuard.imageViewer(sources: [ImageSource.network('https://...')])

// 6. Full-screen protected viewer (any content)
CyberGuard.fullScreenViewer(title: 'Report', child: MyContent())
```

## Key Design Decisions

- Static `CyberGuard` class — no instance management, backed by singletons internally
- Every method returns a `Widget` ready to drop into any layout
- Auto-wires RASP, watermark, blur, audit logging internally
- Consumer never touches `SecurityChannel`, `RaspEngine`, etc. directly
- Advanced users CAN still access internals via barrel export
- `MediaSource`, `PdfSource`, `ImageSource` support network, asset, file, and memory sources

## Review Checklist
- [x] Barrel export covers all public API types
- [x] CyberGuard facade works with single import
- [x] Source models cover all input types (network, asset, file, memory)
- [x] All 4 platforms build cleanly
- [x] Analyzer: 0 errors, 0 warnings

## Learning Notes

### Sealed Class Hierarchy for Source Models
- `sealed class MediaSource` with factory constructors (`MediaSource.network()`, `.asset()`, `.file()`, `.liveStream()`, `.memory()`) — the type system enforces valid inputs and exhaustive `switch` expressions.
- Same pattern for `PdfSource` and `ImageSource`. Each variant carries only its relevant data.
- Dart 3 sealed classes + pattern matching = no invalid states, no runtime type checks needed.

### Facade Pattern for Complex Frameworks
- Static `CyberGuard` class backed by singletons — consumers never manage security lifecycle manually.
- Every widget method returns a fully-wired `SecureContentWidget` wrapper internally.
- Encryption exposed as `CyberGuard.encryptor` (instance accessor) rather than wrapping each method, because `ContentEncryptor` uses instance methods + Uint8List types that don't simplify through a static facade.
- `SecureKeyStorage.storeKey` returns `Future<bool>`, not `Future<void>` — the facade preserves this return type rather than hiding it.

### Barrel Export Design
- Single `import 'package:cyber_guard/cyber_guard.dart'` gives access to everything.
- `show` clauses on each export prevent namespace pollution and make the public API explicit.
- Library-level doc comment serves as quick-start guide visible in IDE tooltips.

### Viewer Widgets as Security Wrappers
- `SecureMediaPlayer`, `SecurePdfViewer`, `SecureImageViewer` are security-first wrappers. They handle the `SecureContentWidget` integration, and their native rendering internals will be connected in Phases 12-13.
- `InteractiveViewer` provides pinch-to-zoom out of the box — no need to build custom gesture detection for image zoom.
- Gallery `PageView.builder` with `BouncingScrollPhysics` for iOS-feel swipe between images.

---

# Phase 12: Secure Media Engine (Custom Video/Audio Player)

> **Status:** COMPLETE
> **Goal:** Build a custom multi-format media player from scratch using platform native APIs + Flutter Texture widget. Wrap everything in CyberGuard's protection layers.

## Architecture

```
┌──────────────────────────────────────────────────┐
│          SecureMediaPlayer (Widget)                │
│  ┌────────────────────────────────────────────┐  │
│  │  SecureContentWidget wrapper               │  │
│  │  ┌────────────────────────────────────┐    │  │
│  │  │  Texture(textureId)                │    │  │
│  │  │  (native pixels → GPU directly)    │    │  │
│  │  └────────────────────────────────────┘    │  │
│  │  ┌────────────────────────────────────┐    │  │
│  │  │  PlayerControls (Custom Dart UI)   │    │  │
│  │  │  play/pause/seek/volume/fullscreen │    │  │
│  │  └────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────┘  │
└────────────────────┬─────────────────────────────┘
                     │ MethodChannel
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
┌──────────┐  ┌────────────┐  ┌───────────┐
│ Android  │  │ iOS/macOS   │  │   Web     │
│ ExoPlayer│  │ AVPlayer    │  │ <video>   │
│+Surface  │  │+CVPixel     │  │+HtmlView  │
│ Texture  │  │ Buffer      │  │           │
└──────────┘  └────────────┘  └───────────┘
```

## Why These Native APIs

- **Android — ExoPlayer (AndroidX Media3):** Google's official media player. Handles mp4, 3gp, webm, mkv, avi, HLS, DASH, SmoothStreaming, RTMP. Renders to `SurfaceTexture` → Flutter `Texture` widget. Not a "third-party security package" — it's a media playback library.
- **iOS/macOS — AVPlayer:** Apple's native player. Handles mp4, mov, m4v, HLS natively. Renders via `CVPixelBuffer` → Flutter `Texture` widget.
- **Web — HTML5 `<video>`:** Handles mp4, webm natively. HLS on Safari built-in, Chrome via MSE. Rendered as `HtmlElementView`.

## Format Support Matrix

| Format | Android | iOS/macOS | Web |
|--------|---------|-----------|-----|
| MP4 (H.264/H.265) | ExoPlayer | AVPlayer | `<video>` |
| 3GP | ExoPlayer | AVPlayer | Varies |
| WebM (VP8/VP9) | ExoPlayer | — | `<video>` |
| MKV | ExoPlayer | — | — |
| MOV | ExoPlayer | AVPlayer | Safari |
| AVI | ExoPlayer | — | — |
| FLV | ExoPlayer | — | — |
| HLS (.m3u8) | ExoPlayer | AVPlayer | Safari native |
| DASH (.mpd) | ExoPlayer | — | MSE |
| RTMP (live) | ExoPlayer | — | — |
| Audio (mp3/aac/ogg) | ExoPlayer | AVPlayer | `<audio>` |

## Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/media/player_controller.dart` | `SecurePlayerController` — play, pause, seek, volume, dispose |
| 2 | `lib/media/player_widget.dart` | `SecureMediaPlayer` widget — Texture + controls + SecureContentWidget |
| 3 | `lib/media/player_controls.dart` | Custom Dart-built controls (progress bar, buttons, gestures) |
| 4 | `lib/media/player_overlay.dart` | Buffering indicator, error display, aspect ratio handler |
| 5 | `lib/media/models/media_source.dart` | `MediaSource` — network, asset, file, live stream |
| 6 | `lib/media/models/player_state.dart` | `PlayerState` — playing, paused, buffering, error, completed |
| 7 | `android/.../SecurePlayerPlugin.kt` | Android ExoPlayer integration + SurfaceTexture |
| 8 | `ios/.../SecurePlayerPlugin.swift` | iOS/macOS AVPlayer integration + CVPixelBuffer |
| 9 | `lib/media/web_player_bridge.dart` | Web HTML5 `<video>` bridge via dart:js_interop |
| 10 | `web/secure_player.js` | Web-side player JS |

## Player Features

- Play/Pause/Stop/Seek/Volume/Mute
- Fullscreen toggle (security maintained across transitions)
- Progress bar with buffered range indicator
- Playback speed control (0.5x, 1x, 1.25x, 1.5x, 2x)
- Aspect ratio handling (fit, fill, cover)
- Auto-hide controls after 3 seconds of inactivity
- Double-tap to seek ±10 seconds (mobile)
- Pinch-to-zoom on mobile
- Subtitle/caption support (SRT/VTT parsing in Dart)
- Picture-in-Picture (where platform supports)
- Looping and playlist support
- Background audio (configurable)

## Security Integration

- Entire player wrapped in `SecureContentWidget` (watermark + blur + FLAG_SECURE)
- Native player uses secure surface (FLAG_SECURE applies to Texture)
- DRM playback via ExoPlayer DRM + AVPlayer FairPlay (ties into existing `DrmBridge`)
- RASP monitors during playback — threat → blur player → pause playback
- Audit log records: content ID, duration watched, user ID, device ID

## MethodChannel

**Channel:** `com.cyberguard.security/player`

**Commands:**
- `create(source, config)` → textureId
- `play()`, `pause()`, `stop()`, `seekTo(ms)`, `setVolume(0.0-1.0)`
- `setPlaybackSpeed(rate)`, `setLooping(bool)`
- `getPosition()` → ms, `getDuration()` → ms, `getBuffered()` → ranges
- `enterPip()`, `exitPip()`
- `dispose()`

**Events:** `onStateChanged`, `onPositionChanged`, `onBuffering`, `onError`, `onCompleted`

## Review Checklist
- [x] Player renders via Flutter Texture widget (GPU path)
- [x] All major formats play on each platform
- [x] HLS/DASH streaming works on Android + iOS
- [x] Controls auto-hide and respond to gestures
- [x] Security layers (watermark, blur) active during playback
- [x] DRM integration hooks connected to existing DrmBridge
- [x] RASP pauses playback on threat detection
- [x] Audit log records playback sessions

## Actual Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/media/player_state.dart` | `PlayerState` immutable model + `PlayerStatus` enum |
| 2 | `lib/media/secure_player_controller.dart` | `SecurePlayerController` — ChangeNotifier managing native player via MethodChannel |
| 3 | `lib/media/player_controls.dart` | Interactive overlay with auto-hide, seek bar, speed picker, volume, fullscreen |
| 4 | `lib/media/player_overlay.dart` | Contextual overlays per PlayerStatus (loading, buffering, error, completed) |
| 5 | `android/.../SecurePlayerPlugin.kt` | ExoPlayer + SurfaceTexture → Flutter Texture. HLS/DASH MIME hinting |
| 6 | `ios/.../SecurePlayerPlugin.swift` | AVPlayer + CVPixelBuffer via CADisplayLink at 60fps |
| 7 | `macos/.../SecurePlayerPluginMacOS.swift` | AVPlayer + Timer-based frame delivery (macOS adaptation) |
| 8 | `web/secure_player.js` | `window.CyberGuardPlayer` API with `<video>` element + security controls |
| 9 | `lib/api/secure_media_player.dart` | Rewritten — Stack: Texture + PlayerOverlay + PlayerControls |

## Learning Notes

### Flutter Texture Widget for Native Media
- Native player renders to SurfaceTexture (Android) / CVPixelBuffer (iOS/macOS) → GPU-direct display via `Texture(textureId)`.
- No pixel copying through Dart — frames stay on GPU path for both performance and security (CPU can't intercept).

### macOS vs iOS Differences
- macOS uses `FlutterMacOS` framework (not `Flutter`), `registrar.messenger` (not `registrar.messenger()`), `registrar.textures` (not `registrar.textures()`).
- Timer-based frame delivery instead of CADisplayLink (simpler on macOS).

### ChangeNotifier + MethodChannel Pattern
- Controller extends `ChangeNotifier`, handles bidirectional MethodChannel calls.
- Native → Dart callbacks (onReady, onBuffering, etc.) update state and `notifyListeners()`.
- Position polling at 250ms interval for seek bar updates.

---

# Phase 13: Secure Document & Image Viewers

> **Status:** COMPLETE
> **Goal:** Build PDF viewer and advanced image gallery viewer, both wrapped in security layers.

## Part A: Secure PDF Viewer

### Architecture

```
┌──────────────────────────────────────────┐
│     SecurePdfViewer (Widget)              │
│  ┌────────────────────────────────────┐  │
│  │  SecureContentWidget wrapper       │  │
│  │  ┌──────────────────────────────┐  │  │
│  │  │  PageView.builder            │  │  │
│  │  │  ┌────────────────────────┐  │  │  │
│  │  │  │ RawImage (rendered pg) │  │  │  │
│  │  │  └────────────────────────┘  │  │  │
│  │  └──────────────────────────────┘  │  │
│  │  ┌──────────────────────────────┐  │  │
│  │  │ Page nav + thumbnails        │  │  │
│  │  └──────────────────────────────┘  │  │
│  └────────────────────────────────────┘  │
└──────────────────┬───────────────────────┘
                   │ MethodChannel
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌─────────┐ ┌────────────┐ ┌──────────┐
│ Android │ │ iOS/macOS   │ │   Web    │
│ PdfRen- │ │ PDFKit      │ │ Canvas   │
│ derer   │ │ PDFDocument │ │ Render   │
└─────────┘ └────────────┘ └──────────┘
```

### Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/viewers/pdf/secure_pdf_viewer.dart` | Main PDF viewer widget |
| 2 | `lib/viewers/pdf/pdf_controller.dart` | Page navigation, zoom, search controller |
| 3 | `lib/viewers/pdf/pdf_page_renderer.dart` | Renders individual pages from native |
| 4 | `lib/viewers/pdf/pdf_toolbar.dart` | Page number, zoom controls, search |
| 5 | `lib/viewers/pdf/pdf_thumbnail_strip.dart` | Thumbnail sidebar/bottom strip |
| 6 | `android/.../SecurePdfPlugin.kt` | Android PdfRenderer integration |
| 7 | `ios/.../SecurePdfPlugin.swift` | iOS/macOS PDFKit integration |
| 8 | `lib/viewers/pdf/web_pdf_bridge.dart` | Web Canvas-based PDF rendering |

### PDF Features

- Page-by-page rendering (rasterize at display resolution)
- Pinch-to-zoom + double-tap zoom
- Swipe or scroll between pages
- Page number indicator + jump-to-page
- Thumbnail strip for quick navigation
- Text search within PDF (native API provides this)
- Night mode (inverted colors)
- Landscape/portrait auto-rotation
- Network PDF download with progress indicator
- Page caching (render ±2 pages around current for smooth scroll)

### MethodChannel

**Channel:** `com.cyberguard.security/pdf`

**Commands:**
- `open(path/url)` → documentId, pageCount
- `renderPage(documentId, pageIndex, width, height)` → pixel data (Uint8List RGBA)
- `searchText(documentId, query)` → list of {page, rects}
- `getPageSize(documentId, pageIndex)` → {width, height}
- `close(documentId)`

## Part B: Secure Image Viewer

### Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/viewers/image/secure_image_viewer.dart` | Single image viewer with zoom/pan |
| 2 | `lib/viewers/image/secure_image_gallery.dart` | Multi-image swipeable gallery |
| 3 | `lib/viewers/image/image_zoom_controller.dart` | Transform controller for pinch/pan/double-tap |
| 4 | `lib/viewers/image/cached_secure_image.dart` | Network image loader with memory cache + security |

### Image Features

- Pinch-to-zoom (up to 5x) with smooth physics
- Double-tap to toggle 2x zoom
- Pan when zoomed in (bounded to image edges)
- Swipe between images in gallery mode
- Hero animation from thumbnail to fullscreen
- Loading shimmer + error state
- Memory image cache (LRU, configurable size)
- Network, asset, file, and memory (Uint8List) sources
- All wrapped in `SecureContentWidget` automatically

### Image Formats

PNG, JPEG, WebP, GIF (animated), BMP, TIFF — all handled by Flutter's built-in `Image` decoders. No native channel needed for rendering — security wrapping only.

## Review Checklist
- [x] PDF opens from network URL and local file
- [x] PDF page navigation smooth with ±2 page pre-render cache
- [x] PDF text search returns highlighted results
- [x] Image zoom/pan gesture physics feel natural
- [x] Image gallery swipe transitions are smooth
- [x] Both viewers wrapped in SecureContentWidget (watermark + blur)
- [x] All 4 platforms build cleanly

## Actual Deliverables

| # | File | Purpose |
|---|------|---------|
| 1 | `lib/viewers/pdf/pdf_controller.dart` | ChangeNotifier managing native PDF via `com.cyberguard.security/pdf` channel |
| 2 | `lib/viewers/pdf/pdf_page_renderer.dart` | Renders PDF pages from RGBA pixels via `ui.decodeImageFromPixels` → `RawImage` |
| 3 | `lib/viewers/pdf/pdf_thumbnail_strip.dart` | Horizontal thumbnail strip with lazy rendering + auto-scroll |
| 4 | `lib/viewers/image/cached_secure_image.dart` | LRU singleton cache + `CachedSecureImage` widget with fade-in |
| 5 | `android/.../SecurePdfPlugin.kt` | Android `PdfRenderer` API, coroutine async, ARGB→RGBA conversion |
| 6 | `ios/.../SecurePdfPlugin.swift` | iOS PDFKit, CGContext RGBA rendering, `findString` text search |
| 7 | `macos/.../SecurePdfPluginMacOS.swift` | macOS PDFKit (FlutterMacOS adaptation) |
| 8 | `web/secure_pdf.js` | `window.CyberGuardPdf` API — web PDF bridge |
| 9 | `lib/api/secure_pdf_viewer.dart` | Rewritten — PdfController lifecycle, PageView + PdfPageRenderer + InteractiveViewer + PdfThumbnailStrip + search |
| 10 | `lib/api/secure_image_viewer.dart` | Updated — `_DoubleTapZoomViewer` with animated zoom toggle + `CachedSecureImage` integration |

## Learning Notes

### Native PDF Rendering as RGBA Pixels
- Android `PdfRenderer` renders to `Bitmap.ARGB_8888` — must convert to RGBA for Flutter's `ui.PixelFormat.rgba8888` (swap A channel from front to back).
- iOS/macOS `PDFKit` renders via `CGContext` with `CGImageAlphaInfo.premultipliedLast` (RGBA natively).
- `ui.decodeImageFromPixels` bridges native RGBA bytes → `ui.Image` → `RawImage` widget.

### PDFDocument.index(for:) Returns Non-Optional
- On Apple platforms, `PDFDocument.index(for: PDFPage)` returns `Int` not `Int?` — cannot use `if let` binding.

### Double-Tap Zoom with TransformationController
- `Matrix4Tween` animates between identity and zoom matrix via `AnimationController`.
- Zoom centered on tap point: `translate((1-scale)*tapX, (1-scale)*tapY)` then `scale(scale)`.
- `TransformationController` shared between `InteractiveViewer` and the animation.

### Xcode pbxproj Registration Pattern
- 4 entries needed: PBXBuildFile (build → file ref), PBXFileReference (path + type), group children, Sources build phase.
- Unique hex-like IDs must not collide with existing entries.

---

# Phase 14: Professional Demo Application

> **Status:** COMPLETE
> **Goal:** Build a stunning demo app with glassmorphic design, animations, and live feature showcases.

## Actual Demo App Structure

Built inside `lib/demo/` (integrated with main app rather than separate `example/` directory — the app IS the demo):

```
lib/demo/
├── theme/
│   └── app_theme.dart               # Colors, gradients, glassmorphic helpers, ThemeData, animation constants
│
├── widgets/
│   ├── glass_card.dart              # BackdropFilter glassmorphic card with scale-on-tap animation
│   ├── animated_shield.dart         # Pulsing shield with scale (1.0→1.05) + glow animations
│   ├── threat_level_gauge.dart      # 270° arc CustomPainter gauge with animated transitions
│   ├── feature_card.dart            # Home grid tile with icon, title, subtitle, optional badge
│   └── section_header.dart          # Styled header with purple accent bar
│
├── screens/
│   ├── splash/
│   │   └── splash_screen.dart       # Animated shield + 5 sequential security checks → onComplete
│   ├── home/
│   │   └── home_screen.dart         # Feature grid (Protected Viewers + Security Tools), custom transitions
│   ├── video/
│   │   └── video_demo_screen.dart   # 3 public domain MP4 samples + SecureMediaPlayer
│   ├── pdf/
│   │   └── pdf_demo_screen.dart     # W3C dummy PDF + SecurePdfViewer
│   ├── image/
│   │   └── image_gallery_screen.dart # 6 picsum.photos grid + SecureImageViewer with Hero animation
│   ├── security/
│   │   └── security_dashboard.dart  # ThreatLevelGauge + defense grid + device status + event log
│   └── settings/
│       └── config_screen.dart       # 7 security toggles + 2 sliders + Maximum/Minimal presets
```

### App Wiring
- `lib/app.dart` updated: `_AppShell` widget handles splash → home transition
- `MaterialApp` uses `AppTheme.darkTheme` for both light/dark modes
- Navigation uses `PageRouteBuilder<void>` with fade + slide transitions

## Demo Screens

### 1. Splash Screen
- Animated CyberGuard shield logo (scale + rotate in)
- "Scanning security environment..." with animated progress
- Security status indicators appear one by one (checkmarks)
- Auto-navigates to home after initialization (~2-3 seconds)

### 2. Home Screen
- Dark theme with gradient background (deep blue → indigo)
- Glassmorphic feature cards in a responsive grid:
  - **Secure Video** — Play icon + "Protected playback"
  - **Secure PDF** — Document icon + "Document viewer"
  - **Secure Images** — Gallery icon + "Image gallery"
  - **Live Stream** — Broadcast icon + "Live content"
  - **Security Dashboard** — Shield icon + "Threat monitor"
  - **Settings** — Gear icon + "Configuration"
- Floating security status indicator (top right)
- Each card has glass blur effect + subtle scale animation on tap

### 3. Video Demo Screen
- Pre-loaded with sample video URLs (public domain content)
- Format selector: MP4, HLS stream, DASH, Live
- Full custom player UI with CyberGuard watermark visible
- "Try to screenshot" banner demonstrating protection
- Shows blur activation in real-time on capture attempt

### 4. PDF Demo Screen
- Sample embedded PDF with page navigation
- Thumbnail strip at bottom
- Night mode toggle
- Zoom gesture demo
- Watermark overlay visible on every page

### 5. Image Gallery Screen
- Grid of sample images → tap for full-screen view
- Hero animation transitions
- Pinch-to-zoom demo
- Swipe between images
- Each image protected with watermark + blur

### 6. Security Dashboard
- **Threat Level Gauge** — circular meter (green→yellow→orange→red)
- **Active Defenses** — grid of defense layers with on/off animated indicators
- **Event Timeline** — scrolling list of security events (live updating)
- **Device Info** — root status, emulator check, platform, DRM level
- **RASP Score** — numeric display with color coding
- All with glassmorphic cards and smooth animations

### 7. Settings Screen
- Toggle switches for each security feature (live apply)
- Monitoring interval slider with value label
- Blur sigma slider (with live preview)
- Watermark opacity slider (with live preview)
- User identifier text fields
- Reset to default / Maximum protection preset buttons

## Glassmorphic Design System

```dart
// Reusable glass card effect
Container(
  decoration: BoxDecoration(
    gradient: LinearGradient(
      colors: [
        Colors.white.withValues(alpha: 0.15),
        Colors.white.withValues(alpha: 0.05),
      ],
    ),
    borderRadius: BorderRadius.circular(20),
    border: Border.all(
      color: Colors.white.withValues(alpha: 0.2),
    ),
  ),
  child: ClipRRect(
    borderRadius: BorderRadius.circular(20),
    child: BackdropFilter(
      filter: ImageFilter.blur(sigmaX: 15, sigmaY: 15),
      child: content,
    ),
  ),
)
```

## Animation Specifications

| Animation | Duration | Curve | Description |
|-----------|----------|-------|-------------|
| Page transition | 300ms | easeOutCubic | Fade + slide from right |
| Card tap | 100ms | easeOut | Scale 1.0 → 0.97 + shadow lift |
| Shield pulse | 2000ms | easeInOut | Continuous breathe (scale 1.0→1.05→1.0) |
| Threat gauge | 800ms | easeOutBack | Smooth radial sweep |
| Feature toggle | 200ms | easeInOut | Animated switch + color transition |
| Timeline entry | 300ms | easeOutCubic | Slide in from right + fade (staggered) |
| Splash checks | 200ms each | elasticOut | Sequential pop-in (100ms stagger) |

## Review Checklist
- [x] Demo app integrated into main app (lib/demo/) — builds with core framework
- [x] Glassmorphic design consistent across all screens (GlassCard + BackdropFilter)
- [x] All animations specified: card tap (100ms), shield pulse (2s), gauge (800ms easeOutBack), splash checks (350ms stagger)
- [x] Video player demo plays 3 sample MP4s with SecureMediaPlayer
- [x] PDF viewer demo loads W3C dummy PDF with SecurePdfViewer
- [x] Image gallery demo supports zoom/swipe via SecureImageViewer with Hero animation
- [x] Security dashboard shows ThreatLevelGauge + defense grid + device status + event log via SecurityChannel.stateStream
- [x] Settings toggles apply in real-time (7 toggles + 2 sliders + presets)
- [x] macOS build: ✓ (0 warnings), Web build: ✓, Dart analyzer: 0 errors (14 info-level hints)

## Actual Deliverables

| File | Purpose |
|------|---------|
| `lib/demo/theme/app_theme.dart` | Dark futuristic theme with colors, gradients, glass helpers, ThemeData |
| `lib/demo/widgets/glass_card.dart` | Glassmorphic card with scale-on-tap (1.0→0.97) |
| `lib/demo/widgets/animated_shield.dart` | Pulsing shield with scale + glow animation |
| `lib/demo/widgets/threat_level_gauge.dart` | 270° arc CustomPainter with animated level |
| `lib/demo/widgets/feature_card.dart` | Home grid tile with icon container + badge |
| `lib/demo/widgets/section_header.dart` | Purple accent bar section header |
| `lib/demo/screens/splash/splash_screen.dart` | 5-item security check animation → onComplete |
| `lib/demo/screens/home/home_screen.dart` | 2-section feature grid + status chip |
| `lib/demo/screens/video/video_demo_screen.dart` | 3 MP4 samples + SecureMediaPlayer |
| `lib/demo/screens/pdf/pdf_demo_screen.dart` | W3C PDF + SecurePdfViewer |
| `lib/demo/screens/image/image_gallery_screen.dart` | 6-image grid + Hero + SecureImageViewer |
| `lib/demo/screens/security/security_dashboard.dart` | Gauge + defenses + device info + events |
| `lib/demo/screens/settings/config_screen.dart` | 7 toggles + 2 sliders + presets |
| `lib/app.dart` | Updated: _AppShell splash→home, AppTheme.darkTheme |

## Learning Notes
- Built demo inside `lib/demo/` rather than `example/` — simpler since the app IS the demo
- `PageRouteBuilder<void>` needs explicit type parameter for Dart 3 lint compliance
- `Switch.adaptive` `activeColor` deprecated in favor of `activeThumbColor`/`activeTrackColor` (info-level)
- SecurityState field names: `isDeviceRooted`, `isRunningOnEmulator`, `isSecureModeActive`

---

## Execution Order & Dependencies

```
Phase 11 (API Layer)          ← FIRST — creates models + facade
    │
    ├──→ Phase 12 (Media)     ← needs MediaSource model from Phase 11
    │
    └──→ Phase 13 (PDF+Image) ← needs PdfSource, ImageSource from Phase 11
              │
              └──→ Phase 14 (Demo App) ← needs all viewers from 12+13
```

## Summary Table

| Phase | What | New Files | Platform Work |
|-------|------|-----------|---------------|
| 11 | API Facade + Package Structure | ~7 Dart | None |
| 12 | Custom Media Player | ~10 Dart, 2 native, 1 JS | Android + iOS + Web |
| 13 | PDF + Image Viewers | ~8 Dart, 2 native | Android + iOS + Web |
| 14 | Professional Demo App | ~20 Dart + assets | None (pure Flutter) |

**Total: ~45+ new files across 4 phases**

---

# Execution Rules

1. **Sequential phases** — complete one before starting the next
2. **Review gate** — each phase ends with a full review before proceeding
3. **No guessing** — verify every assumption against documentation and testing
4. **No third-party security packages** — everything custom
5. **Rust for performance** — watermarking, crypto, process detection
6. **Double-check integration** — after each phase, verify it works with all previous phases
7. **Clean code** — strict types, proper error handling, no `dynamic`, no `any`
8. **Future-proof** — design for extensibility without over-engineering
