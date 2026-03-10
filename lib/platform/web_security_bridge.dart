import 'web_security_bridge_stub.dart'
    if (dart.library.js_interop) 'web_security_bridge_web.dart';

/// Bridge between Dart and the JavaScript CyberGuardSecurity engine.
///
/// ## Why conditional imports:
///
/// `dart:js_interop` only exists on the web platform. If we import it
/// unconditionally, the app fails to compile on Android/iOS/macOS.
///
/// The conditional import pattern:
/// ```dart
/// import 'stub.dart' if (dart.library.js_interop) 'web.dart';
/// ```
///
/// At compile time:
/// - **Web builds:** `dart.library.js_interop` is true → imports `web.dart`
/// - **Native builds:** `dart.library.js_interop` is false → imports `stub.dart`
///
/// Both files export the same function signature (`createWebSecurityBridge()`),
/// so the code compiles on all platforms.
///
/// ## Architecture:
/// ```
/// SecurityChannel (Dart)
///     │
///     ├── Native (MethodChannel) → Android/iOS/macOS
///     │
///     └── Web (WebSecurityBridge) → security_guard.js
///              │
///              ├── initialize() → CyberGuardSecurity.initialize()
///              ├── activate()   → CyberGuardSecurity.activate()
///              ├── deactivate() → CyberGuardSecurity.deactivate()
///              ├── getStatus()  → CyberGuardSecurity.getStatus()
///              └── onEvent      ← CyberGuardSecurity.onSecurityEvent
/// ```
abstract class WebSecurityBridge {
  /// Initialize the web security engine with configuration.
  void initialize(Map<String, dynamic> config);

  /// Activate all web protections (canvas, devtools, shortcuts, etc.)
  void activate();

  /// Deactivate all web protections.
  void deactivate();

  /// Get current security status (DevTools open, etc.)
  Map<String, bool> getStatus();

  /// Register a callback for security events from JavaScript.
  ///
  /// Events arrive as Maps matching the SecurityEvent schema:
  /// `{type: string, severity: string, timestamp: int, metadata: {}}`
  void setEventCallback(void Function(Map<String, dynamic> event)? callback);

  /// Clean up all resources.
  void dispose();
}

/// Factory function — resolved at compile time via conditional import.
///
/// On web: returns [WebSecurityBridgeImpl] (real JS interop)
/// On native: returns [WebSecurityBridgeStub] (no-op)
// ignore: non_constant_identifier_names
WebSecurityBridge createWebSecurityBridge() => createPlatformBridge();
