import 'dart:ui';

import 'package:flutter/material.dart';

/// Animated blur overlay that activates when security threats are detected.
///
/// ## How it works:
/// - Listens to [isActive] — when true, animates blur from 0 → [maxSigma]
/// - Uses [BackdropFilter] with [ImageFilter.blur] for real-time Gaussian blur
/// - Animation completes in [activationDuration] (default 40ms — well under
///   the 50ms requirement, so content is blurred before the next frame)
/// - When threat clears, blur fades out over [deactivationDuration] (200ms)
///
/// ## Why BackdropFilter:
/// BackdropFilter applies the blur to everything BEHIND this widget in the
/// paint order. This means:
/// 1. We don't need to modify the child widget at all
/// 2. The blur applies to the compositor output — even platform views
/// 3. GPU-accelerated on all platforms
///
/// ## Activation speed:
/// At 60fps, one frame = 16.6ms. Our 40ms activation means the blur is
/// fully applied within 2-3 frames of detection. Combined with the native
/// monitoring loop (50ms interval), total latency from capture start to
/// blur is < 100ms.
class BlurShield extends StatefulWidget {
  const BlurShield({
    super.key,
    required this.isActive,
    this.maxSigma = 30.0,
    this.activationDuration = const Duration(milliseconds: 40),
    this.deactivationDuration = const Duration(milliseconds: 200),
    this.warningMessage = 'Screen capture detected',
    this.showWarning = true,
  });

  /// Whether the blur should be active (true = threat detected).
  final bool isActive;

  /// Maximum blur sigma. 30 = content completely unreadable.
  final double maxSigma;

  /// How fast the blur activates. Must be < 50ms for security requirement.
  final Duration activationDuration;

  /// How fast the blur deactivates when threat clears.
  final Duration deactivationDuration;

  /// Warning message displayed over the blur.
  final String warningMessage;

  /// Whether to show the warning message and icon.
  final bool showWarning;

  @override
  State<BlurShield> createState() => _BlurShieldState();
}

class _BlurShieldState extends State<BlurShield>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _sigmaAnimation;

  @override
  void initState() {
    super.initState();

    // Controller duration is set dynamically based on direction
    _controller = AnimationController(
      vsync: this,
      duration: widget.activationDuration,
      reverseDuration: widget.deactivationDuration,
    );

    _sigmaAnimation = Tween<double>(
      begin: 0.0,
      end: widget.maxSigma,
    ).animate(CurvedAnimation(
      parent: _controller,
      // EaseOut for activation: starts fast, ends smooth
      // EaseIn for deactivation: starts smooth, ends fast
      curve: Curves.easeOut,
      reverseCurve: Curves.easeIn,
    ));

    // If already active on mount, snap to blurred state immediately
    if (widget.isActive) {
      _controller.value = 1.0;
    }
  }

  @override
  void didUpdateWidget(BlurShield oldWidget) {
    super.didUpdateWidget(oldWidget);

    if (widget.isActive != oldWidget.isActive) {
      if (widget.isActive) {
        // THREAT DETECTED — activate blur as fast as possible
        _controller.duration = widget.activationDuration;
        _controller.forward();
      } else {
        // Threat cleared — deactivate blur with smooth transition
        _controller.reverseDuration = widget.deactivationDuration;
        _controller.reverse();
      }
    }

    // Update max sigma if config changed
    if (widget.maxSigma != oldWidget.maxSigma) {
      _sigmaAnimation = Tween<double>(
        begin: 0.0,
        end: widget.maxSigma,
      ).animate(CurvedAnimation(
        parent: _controller,
        curve: Curves.easeOut,
        reverseCurve: Curves.easeIn,
      ));
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _sigmaAnimation,
      builder: (context, child) {
        final sigma = _sigmaAnimation.value;

        // Don't render anything when blur is fully inactive
        // (avoid the cost of BackdropFilter with sigma=0)
        if (sigma < 0.1) return const SizedBox.shrink();

        return ClipRect(
          // ClipRect is required for BackdropFilter to work correctly
          child: BackdropFilter(
            filter: ImageFilter.blur(
              sigmaX: sigma,
              sigmaY: sigma,
              tileMode: TileMode.clamp,
            ),
            child: Container(
              color: Colors.black.withValues(
                // Semi-transparent overlay that scales with blur intensity
                alpha: (sigma / widget.maxSigma) * 0.6,
              ),
              child: widget.showWarning && sigma > widget.maxSigma * 0.5
                  ? child
                  : null,
            ),
          ),
        );
      },
      child: widget.showWarning ? _buildWarningContent(context) : null,
    );
  }

  Widget _buildWarningContent(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(
            Icons.shield,
            size: 64,
            color: Colors.white,
          ),
          const SizedBox(height: 16),
          Text(
            widget.warningMessage,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w600,
              decoration: TextDecoration.none,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),
          const Text(
            'Content is protected',
            style: TextStyle(
              color: Colors.white70,
              fontSize: 14,
              fontWeight: FontWeight.w400,
              decoration: TextDecoration.none,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}
