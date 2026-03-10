import 'package:flutter/material.dart';

import 'app.dart';
import 'core/security/security_channel.dart';
import 'core/security/security_config.dart';
import 'platform/platform_security.dart';

/// Application entry point.
///
/// ## Initialization Order (critical):
/// 1. Ensure Flutter bindings are ready
/// 2. Initialize security channel with config BEFORE rendering any UI
/// 3. Run the app — all widgets can now access security state
///
/// Security initialization happens before `runApp` because native
/// protection flags (FLAG_SECURE, UIScreen observation) must be active
/// before any frame is rendered. If we initialized lazily, there would
/// be a window where content is visible without protection.
void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Configure security based on platform capabilities
  final config = SecurityConfig.maximum.copyWith(
    // These will be set dynamically when user authenticates:
    watermarkUserIdentifier: '',
    watermarkDisplayName: '',
    // Root/jailbreak detection only on mobile
    enableRootDetection: PlatformSecurity.supportsRootDetection,
    enableEmulatorDetection: PlatformSecurity.supportsRootDetection,
  );

  // Initialize the security bridge to native code
  await SecurityChannel.instance.initialize(config);

  runApp(const CyberGuardApp());
}
