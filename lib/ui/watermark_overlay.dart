import 'dart:math' as math;

import 'package:flutter/foundation.dart' show listEquals;
import 'package:flutter/material.dart';

/// Renders a semi-transparent watermark overlay across the entire surface.
///
/// ## How it works:
/// - CustomPainter draws rotated text in a repeating grid pattern
/// - Each cell shows: user email, display name, and timestamp
/// - Text is drawn at very low opacity (default 0.08) — visible in
///   screenshots/recordings but not distracting during normal use
/// - Rotation (-30°) prevents easy cropping or removal
///
/// ## Why CustomPainter:
/// Using CustomPainter instead of overlapping Text widgets gives us:
/// 1. Single paint pass (no layout overhead per text instance)
/// 2. Precise control over rotation and spacing
/// 3. No widget tree bloat (one painter vs hundreds of Text widgets)
/// 4. Renders in the compositor layer — visible in any capture method
class WatermarkOverlay extends StatelessWidget {
  const WatermarkOverlay({
    super.key,
    required this.userIdentifier,
    this.displayName = '',
    this.opacity = 0.08,
    this.fontSize = 12.0,
    this.rotation = -30.0,
    this.spacing = 160.0,
    this.color,
  });

  /// User identifier shown in watermark (email, user ID).
  final String userIdentifier;

  /// Display name shown alongside identifier.
  final String displayName;

  /// Watermark text opacity. 0.08 = barely visible. Range: 0.0–1.0.
  final double opacity;

  /// Font size for watermark text.
  final double fontSize;

  /// Rotation angle in degrees. Negative = counter-clockwise.
  final double rotation;

  /// Spacing between watermark text repetitions (in pixels).
  final double spacing;

  /// Text color override. Defaults to white on dark, black on light.
  final Color? color;

  @override
  Widget build(BuildContext context) {
    // Skip rendering if no identifier is set
    if (userIdentifier.isEmpty) return const SizedBox.shrink();

    final brightness = Theme.of(context).brightness;
    final textColor = color ??
        (brightness == Brightness.dark
            ? Colors.white.withValues(alpha: opacity)
            : Colors.black.withValues(alpha: opacity));

    // Format timestamp as date + time for forensic traceability
    final now = DateTime.now();
    final timestamp =
        '${now.year}-${_pad(now.month)}-${_pad(now.day)} '
        '${_pad(now.hour)}:${_pad(now.minute)}';

    // Build watermark lines
    final lines = <String>[
      if (displayName.isNotEmpty) displayName,
      userIdentifier,
      timestamp,
    ];

    return IgnorePointer(
      // Watermark should never intercept touches
      child: RepaintBoundary(
        // Isolate repaints — watermark only repaints when text changes
        child: CustomPaint(
          painter: _WatermarkPainter(
            lines: lines,
            color: textColor,
            fontSize: fontSize,
            rotationDegrees: rotation,
            spacing: spacing,
          ),
          // Expand to fill parent
          size: Size.infinite,
        ),
      ),
    );
  }

  static String _pad(int n) => n.toString().padLeft(2, '0');
}

/// CustomPainter that draws repeating rotated text across the canvas.
///
/// Paint algorithm:
/// 1. Rotate canvas by [rotationDegrees]
/// 2. Calculate expanded bounds (rotation makes the visible area larger)
/// 3. Draw text at regular grid intervals across the expanded bounds
/// 4. Each grid cell contains all [lines] stacked vertically
class _WatermarkPainter extends CustomPainter {
  _WatermarkPainter({
    required this.lines,
    required this.color,
    required this.fontSize,
    required this.rotationDegrees,
    required this.spacing,
  });

  final List<String> lines;
  final Color color;
  final double fontSize;
  final double rotationDegrees;
  final double spacing;

  @override
  void paint(Canvas canvas, Size size) {
    if (lines.isEmpty || size.isEmpty) return;

    final textStyle = TextStyle(
      color: color,
      fontSize: fontSize,
      fontWeight: FontWeight.w400,
      letterSpacing: 0.5,
    );

    // Convert degrees to radians
    final radians = rotationDegrees * math.pi / 180.0;

    // Save canvas state, apply rotation around center
    canvas.save();
    canvas.translate(size.width / 2, size.height / 2);
    canvas.rotate(radians);
    canvas.translate(-size.width / 2, -size.height / 2);

    // After rotation, we need to paint beyond the original bounds
    // to cover corners. The diagonal of the canvas is the maximum
    // extent we need to cover.
    final diagonal = math.sqrt(
      size.width * size.width + size.height * size.height,
    );
    final overflow = (diagonal - math.min(size.width, size.height)) / 2 + spacing;

    // Calculate line height for multi-line watermark blocks
    final lineHeight = fontSize * 1.5;
    final blockHeight = lines.length * lineHeight;

    // Draw grid of watermark blocks
    double y = -overflow;
    while (y < size.height + overflow) {
      double x = -overflow;
      while (x < size.width + overflow) {
        _drawWatermarkBlock(canvas, x, y, textStyle, lineHeight);
        x += spacing;
      }
      y += blockHeight + spacing * 0.5;
    }

    canvas.restore();
  }

  /// Draw a single watermark block (all lines stacked vertically).
  void _drawWatermarkBlock(
    Canvas canvas,
    double x,
    double y,
    TextStyle style,
    double lineHeight,
  ) {
    for (int i = 0; i < lines.length; i++) {
      final textSpan = TextSpan(text: lines[i], style: style);
      final painter = TextPainter(
        text: textSpan,
        textDirection: TextDirection.ltr,
        maxLines: 1,
      );
      painter.layout();
      painter.paint(canvas, Offset(x, y + i * lineHeight));
    }
  }

  @override
  bool shouldRepaint(_WatermarkPainter oldDelegate) {
    return !listEquals(oldDelegate.lines, lines) ||
        oldDelegate.color != color ||
        oldDelegate.fontSize != fontSize ||
        oldDelegate.rotationDegrees != rotationDegrees ||
        oldDelegate.spacing != spacing;
  }
}
