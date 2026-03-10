import 'dart:async';

import 'package:flutter/material.dart';

import '../core/security/security_channel.dart';
import '../core/security/security_config.dart';
import '../core/security/security_state.dart';
import 'blur_shield.dart';
import 'watermark_overlay.dart';

/// Wraps any child widget with the full CyberGuard protection stack.
///
/// ## What it does:
/// 1. **Lifecycle management** — Calls `enterSecureMode()` when mounted,
///    `exitSecureMode()` when unmounted. This activates/deactivates
///    native flags (FLAG_SECURE, NSWindow.sharingType, etc.)
/// 2. **Watermark overlay** — Draws semi-transparent user info across
///    the content surface (email, name, timestamp)
/// 3. **Blur shield** — Activates Gaussian blur when threats are detected
///    (screen capture, debugger, root, etc.)
///
/// ## Usage:
/// ```dart
/// SecureContentWidget(
///   child: Image.network('https://example.com/secure-content.jpg'),
/// )
/// ```
///
/// ## Widget tree produced:
/// ```
/// Stack (fill)
///   ├── child (your content)
///   ├── WatermarkOverlay (semi-transparent, IgnorePointer)
///   └── BlurShield (Positioned.fill, animated BackdropFilter)
/// ```
///
/// The order matters: blur is on TOP of watermark, so when blur activates,
/// even the watermark becomes unreadable. This prevents attackers from
/// reading the watermark text in a capture (which would identify the user).
class SecureContentWidget extends StatefulWidget {
  const SecureContentWidget({
    super.key,
    required this.child,
    this.config,
    this.onSecurityEvent,
  });

  /// The content to protect.
  final Widget child;

  /// Optional config override. If null, uses SecurityChannel's current config.
  final SecurityConfig? config;

  /// Optional callback when security events occur (for logging/analytics).
  final void Function(SecurityState state)? onSecurityEvent;

  @override
  State<SecureContentWidget> createState() => _SecureContentWidgetState();
}

class _SecureContentWidgetState extends State<SecureContentWidget> {
  SecurityState _securityState = const SecurityState();
  StreamSubscription<SecurityState>? _stateSubscription;
  bool _secureModeEntered = false;

  SecurityConfig get _config =>
      widget.config ?? SecurityChannel.instance.config;

  @override
  void initState() {
    super.initState();

    // Enter secure mode — activates native protection flags
    _enterSecureMode();

    // Listen to security state changes
    _stateSubscription = SecurityChannel.instance.stateStream.listen(
      _onSecurityStateChanged,
    );

    // Sync with current state (in case events arrived before we subscribed)
    _securityState = SecurityChannel.instance.currentState;
  }

  @override
  void dispose() {
    _stateSubscription?.cancel();
    _exitSecureMode();
    super.dispose();
  }

  Future<void> _enterSecureMode() async {
    if (_secureModeEntered) return;
    _secureModeEntered = true;
    await SecurityChannel.instance.enterSecureMode();
  }

  Future<void> _exitSecureMode() async {
    if (!_secureModeEntered) return;
    _secureModeEntered = false;
    await SecurityChannel.instance.exitSecureMode();
  }

  void _onSecurityStateChanged(SecurityState state) {
    setState(() {
      _securityState = state;
    });
    widget.onSecurityEvent?.call(state);
  }

  @override
  Widget build(BuildContext context) {
    final config = _config;
    final shouldBlur = config.enableBlurOnCapture &&
        _securityState.shouldBlurContent;

    return Stack(
      fit: StackFit.expand,
      children: [
        // Layer 1: The actual content
        widget.child,

        // Layer 2: Visible watermark overlay
        if (config.enableWatermark)
          Positioned.fill(
            child: WatermarkOverlay(
              userIdentifier: config.watermarkUserIdentifier,
              displayName: config.watermarkDisplayName,
              opacity: config.watermarkOpacity,
            ),
          ),

        // Layer 3: Blur shield (on top of everything, including watermark)
        Positioned.fill(
          child: BlurShield(
            isActive: shouldBlur,
            maxSigma: config.blurSigma,
          ),
        ),
      ],
    );
  }
}
