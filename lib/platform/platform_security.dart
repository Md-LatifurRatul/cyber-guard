import 'package:flutter/foundation.dart';

/// Detects the current platform and provides platform-specific capabilities.
///
/// Used to determine which security features are available and how to
/// configure them. This avoids runtime Platform.isX checks scattered
/// throughout the codebase.
class PlatformSecurity {
  PlatformSecurity._();

  /// The detected platform type.
  static SecurityPlatform get current {
    if (kIsWeb) return SecurityPlatform.web;

    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return SecurityPlatform.android;
      case TargetPlatform.iOS:
        return SecurityPlatform.ios;
      case TargetPlatform.macOS:
        return SecurityPlatform.macos;
      case TargetPlatform.windows:
        return SecurityPlatform.windows;
      case TargetPlatform.linux:
        return SecurityPlatform.linux;
      case TargetPlatform.fuchsia:
        return SecurityPlatform.unsupported;
    }
  }

  /// Whether the current platform supports native security features.
  static bool get isNativeSecurityAvailable {
    final platform = current;
    return platform == SecurityPlatform.android ||
        platform == SecurityPlatform.ios ||
        platform == SecurityPlatform.macos;
  }

  /// Whether the current platform supports GPU-only rendering.
  static bool get supportsGpuProtection {
    final platform = current;
    return platform == SecurityPlatform.android ||
        platform == SecurityPlatform.ios ||
        platform == SecurityPlatform.macos ||
        platform == SecurityPlatform.web;
  }

  /// Whether the current platform supports hardware security modules.
  static bool get supportsHsm {
    final platform = current;
    return platform == SecurityPlatform.android ||
        platform == SecurityPlatform.ios;
  }

  /// Whether the current platform supports Rust FFI.
  static bool get supportsRustFfi {
    // Rust FFI works on all native platforms.
    // On web, Rust compiles to WASM instead.
    return !kIsWeb;
  }

  /// Whether root/jailbreak detection is relevant for this platform.
  static bool get supportsRootDetection {
    final platform = current;
    return platform == SecurityPlatform.android ||
        platform == SecurityPlatform.ios;
  }

  /// Human-readable platform name for logging.
  static String get platformName => current.name;
}

/// Supported platform types for security feature dispatch.
enum SecurityPlatform {
  android,
  ios,
  macos,
  web,
  windows,
  linux,
  unsupported,
}
