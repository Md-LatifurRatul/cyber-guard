import 'dart:ui';

import 'package:flutter/material.dart';

/// CyberGuard demo app theme — dark, futuristic, glassmorphic.
class AppTheme {
  AppTheme._();

  // ─── Colors ───

  static const Color primary = Color(0xFF6C63FF);
  static const Color primaryLight = Color(0xFF8B83FF);
  static const Color accent = Color(0xFF00E5FF);
  static const Color accentGreen = Color(0xFF00E676);
  static const Color warning = Color(0xFFFFAB00);
  static const Color danger = Color(0xFFFF5252);

  static const Color backgroundDark = Color(0xFF0A0E21);
  static const Color backgroundMid = Color(0xFF111633);
  static const Color surfaceDark = Color(0xFF161B3A);
  static const Color surfaceLight = Color(0xFF1D2246);

  static const Color textPrimary = Color(0xFFF0F0FF);
  static const Color textSecondary = Color(0xFF8A8FB0);
  static const Color textMuted = Color(0xFF5A5F80);

  // ─── Gradients ───

  static const LinearGradient backgroundGradient = LinearGradient(
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
    colors: [Color(0xFF0A0E21), Color(0xFF141852), Color(0xFF0A0E21)],
  );

  static const LinearGradient primaryGradient = LinearGradient(
    colors: [Color(0xFF6C63FF), Color(0xFF8B83FF)],
  );

  static const LinearGradient accentGradient = LinearGradient(
    colors: [Color(0xFF00E5FF), Color(0xFF00B0FF)],
  );

  static const LinearGradient shieldGradient = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [Color(0xFF6C63FF), Color(0xFF3F51B5)],
  );

  // ─── Glass Effect ───

  static BoxDecoration glassDecoration({
    double opacity = 0.1,
    double borderOpacity = 0.15,
    double radius = 20,
  }) {
    return BoxDecoration(
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          Colors.white.withValues(alpha: opacity + 0.05),
          Colors.white.withValues(alpha: opacity),
        ],
      ),
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(
        color: Colors.white.withValues(alpha: borderOpacity),
      ),
    );
  }

  static Widget glassContainer({
    required Widget child,
    double opacity = 0.1,
    double borderOpacity = 0.15,
    double radius = 20,
    double blurSigma = 15,
    EdgeInsetsGeometry? padding,
    EdgeInsetsGeometry? margin,
  }) {
    return Container(
      margin: margin,
      decoration: glassDecoration(
        opacity: opacity,
        borderOpacity: borderOpacity,
        radius: radius,
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(radius),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: blurSigma, sigmaY: blurSigma),
          child: Padding(
            padding: padding ?? EdgeInsets.zero,
            child: child,
          ),
        ),
      ),
    );
  }

  // ─── ThemeData ───

  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      useMaterial3: true,
      colorScheme: ColorScheme.fromSeed(
        seedColor: primary,
        brightness: Brightness.dark,
        surface: surfaceDark,
      ),
      scaffoldBackgroundColor: backgroundDark,
      fontFamily: 'Inter',
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        titleTextStyle: TextStyle(
          fontSize: 18,
          fontWeight: FontWeight.w600,
          color: textPrimary,
          letterSpacing: 0.5,
        ),
        iconTheme: IconThemeData(color: textPrimary),
      ),
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          fontSize: 28,
          fontWeight: FontWeight.w700,
          color: textPrimary,
          letterSpacing: -0.5,
        ),
        headlineMedium: TextStyle(
          fontSize: 22,
          fontWeight: FontWeight.w600,
          color: textPrimary,
        ),
        titleLarge: TextStyle(
          fontSize: 18,
          fontWeight: FontWeight.w600,
          color: textPrimary,
        ),
        titleMedium: TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w500,
          color: textPrimary,
        ),
        bodyLarge: TextStyle(
          fontSize: 15,
          color: textSecondary,
          height: 1.5,
        ),
        bodyMedium: TextStyle(
          fontSize: 13,
          color: textSecondary,
        ),
        bodySmall: TextStyle(
          fontSize: 11,
          color: textMuted,
        ),
        labelLarge: TextStyle(
          fontSize: 13,
          fontWeight: FontWeight.w600,
          color: textPrimary,
          letterSpacing: 0.5,
        ),
      ),
    );
  }

  // ─── Animation Constants ───

  static const Duration pageTransition = Duration(milliseconds: 300);
  static const Duration cardTap = Duration(milliseconds: 100);
  static const Duration shieldPulse = Duration(milliseconds: 2000);
  static const Duration gaugeAnimation = Duration(milliseconds: 800);
  static const Duration featureToggle = Duration(milliseconds: 200);
  static const Duration timelineEntry = Duration(milliseconds: 300);
  static const Duration splashCheck = Duration(milliseconds: 200);

  static const Curve defaultCurve = Curves.easeOutCubic;
}
