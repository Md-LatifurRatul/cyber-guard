import 'web_security_bridge.dart';

/// No-op stub for native platforms (Android, iOS, macOS).
///
/// This file is imported when `dart.library.js_interop` is NOT available
/// (i.e., on all native platforms). Every method is a no-op because
/// web security features don't apply to native apps.
WebSecurityBridge createPlatformBridge() => _WebSecurityBridgeStub();

class _WebSecurityBridgeStub implements WebSecurityBridge {
  @override
  void initialize(Map<String, dynamic> config) {}

  @override
  void activate() {}

  @override
  void deactivate() {}

  @override
  Map<String, bool> getStatus() => {
        'isDevToolsOpen': false,
        'isActive': false,
        'isInitialized': false,
      };

  @override
  void setEventCallback(
      void Function(Map<String, dynamic> event)? callback) {}

  @override
  void dispose() {}
}
