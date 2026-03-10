import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

/// Animated pulsing shield icon for splash and branding.
class AnimatedShield extends StatefulWidget {
  const AnimatedShield({
    super.key,
    this.size = 100,
    this.pulse = true,
  });

  final double size;
  final bool pulse;

  @override
  State<AnimatedShield> createState() => _AnimatedShieldState();
}

class _AnimatedShieldState extends State<AnimatedShield>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _scaleAnimation;
  late final Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: AppTheme.shieldPulse,
    );

    _scaleAnimation = Tween<double>(begin: 1.0, end: 1.05).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );

    _glowAnimation = Tween<double>(begin: 0.3, end: 0.7).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );

    if (widget.pulse) {
      _controller.repeat(reverse: true);
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
      animation: _controller,
      builder: (context, child) {
        return Transform.scale(
          scale: _scaleAnimation.value,
          child: Container(
            width: widget.size,
            height: widget.size,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: AppTheme.shieldGradient,
              boxShadow: [
                BoxShadow(
                  color: AppTheme.primary.withValues(
                    alpha: _glowAnimation.value,
                  ),
                  blurRadius: 30,
                  spreadRadius: 5,
                ),
              ],
            ),
            child: Icon(
              Icons.shield_rounded,
              size: widget.size * 0.55,
              color: Colors.white,
            ),
          ),
        );
      },
    );
  }
}
