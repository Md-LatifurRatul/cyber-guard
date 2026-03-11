import 'package:flutter/material.dart';

/// Stub for non-web platforms. Never actually called.
Widget createWebVideoElement({
  required String url,
  required String elementId,
  required bool autoPlay,
  required double volume,
}) {
  return const SizedBox.shrink();
}
