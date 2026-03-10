import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

/// Circular threat level gauge (0.0 = safe green, 1.0 = critical red).
class ThreatLevelGauge extends StatefulWidget {
  const ThreatLevelGauge({
    super.key,
    required this.level,
    this.size = 140,
    this.strokeWidth = 10,
    this.label,
  });

  /// Threat level 0.0 (safe) to 1.0 (critical).
  final double level;
  final double size;
  final double strokeWidth;
  final String? label;

  @override
  State<ThreatLevelGauge> createState() => _ThreatLevelGaugeState();
}

class _ThreatLevelGaugeState extends State<ThreatLevelGauge>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late Animation<double> _animation;
  double _previousLevel = 0;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: AppTheme.gaugeAnimation,
    );
    _animation = Tween<double>(begin: 0, end: widget.level).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeOutBack),
    );
    _controller.forward();
  }

  @override
  void didUpdateWidget(ThreatLevelGauge oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.level != widget.level) {
      _previousLevel = _animation.value;
      _animation =
          Tween<double>(begin: _previousLevel, end: widget.level).animate(
        CurvedAnimation(parent: _controller, curve: Curves.easeOutBack),
      );
      _controller.forward(from: 0);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Color _colorForLevel(double level) {
    if (level < 0.25) return AppTheme.accentGreen;
    if (level < 0.5) return AppTheme.accent;
    if (level < 0.75) return AppTheme.warning;
    return AppTheme.danger;
  }

  String _labelForLevel(double level) {
    if (level < 0.25) return 'SAFE';
    if (level < 0.5) return 'LOW';
    if (level < 0.75) return 'MEDIUM';
    return 'HIGH';
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        final level = _animation.value.clamp(0.0, 1.0);
        final color = _colorForLevel(level);

        return SizedBox(
          width: widget.size,
          height: widget.size,
          child: Stack(
            alignment: Alignment.center,
            children: [
              // Background arc
              CustomPaint(
                size: Size(widget.size, widget.size),
                painter: _GaugePainter(
                  progress: level,
                  color: color,
                  strokeWidth: widget.strokeWidth,
                  backgroundColor:
                      Colors.white.withValues(alpha: 0.08),
                ),
              ),
              // Center text
              Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    '${(level * 100).toInt()}',
                    style: TextStyle(
                      fontSize: widget.size * 0.22,
                      fontWeight: FontWeight.w700,
                      color: color,
                      fontFeatures: const [FontFeature.tabularFigures()],
                    ),
                  ),
                  Text(
                    widget.label ?? _labelForLevel(level),
                    style: TextStyle(
                      fontSize: widget.size * 0.09,
                      fontWeight: FontWeight.w600,
                      color: color.withValues(alpha: 0.8),
                      letterSpacing: 1.5,
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }
}

class _GaugePainter extends CustomPainter {
  _GaugePainter({
    required this.progress,
    required this.color,
    required this.strokeWidth,
    required this.backgroundColor,
  });

  final double progress;
  final Color color;
  final double strokeWidth;
  final Color backgroundColor;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width - strokeWidth) / 2;
    const startAngle = math.pi * 0.75; // 135 degrees
    const sweepTotal = math.pi * 1.5; // 270 degrees

    // Background arc
    final bgPaint = Paint()
      ..color = backgroundColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepTotal,
      false,
      bgPaint,
    );

    // Progress arc
    final progressPaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round
      ..shader = SweepGradient(
        startAngle: startAngle,
        endAngle: startAngle + sweepTotal * progress,
        colors: [color.withValues(alpha: 0.6), color],
      ).createShader(Rect.fromCircle(center: center, radius: radius));

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepTotal * progress,
      false,
      progressPaint,
    );
  }

  @override
  bool shouldRepaint(_GaugePainter oldDelegate) =>
      oldDelegate.progress != progress || oldDelegate.color != color;
}
