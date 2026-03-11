import 'package:flutter/material.dart';

import '../../theme/app_theme.dart';
import '../../widgets/glass_card.dart';
import '../../widgets/section_header.dart';

/// Settings screen for toggling security features live.
class ConfigScreen extends StatefulWidget {
  const ConfigScreen({super.key});

  @override
  State<ConfigScreen> createState() => _ConfigScreenState();
}

class _ConfigScreenState extends State<ConfigScreen> {
  bool _screenCapturePrevention = true;
  bool _watermarkOverlay = true;
  bool _blurOnCapture = true;
  bool _antiDebug = true;
  bool _rootDetection = true;
  bool _integrityCheck = true;
  bool _raspEngine = true;
  double _watermarkOpacity = 0.15;
  double _blurSigma = 20.0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Configuration'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_rounded, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Container(
        decoration: const BoxDecoration(gradient: AppTheme.backgroundGradient),
        child: SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                // Security toggles
                const SectionHeader(title: 'Security Layers'),
                const SizedBox(height: 8),
                GlassCard(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Column(
                    children: [
                      _buildToggle(
                        'Screen Capture Prevention',
                        Icons.screen_lock_portrait_rounded,
                        _screenCapturePrevention,
                        (v) => setState(() => _screenCapturePrevention = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'Watermark Overlay',
                        Icons.water_drop_rounded,
                        _watermarkOverlay,
                        (v) => setState(() => _watermarkOverlay = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'Blur on Capture',
                        Icons.blur_on_rounded,
                        _blurOnCapture,
                        (v) => setState(() => _blurOnCapture = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'Anti-Debug Protection',
                        Icons.bug_report_rounded,
                        _antiDebug,
                        (v) => setState(() => _antiDebug = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'Root/Jailbreak Detection',
                        Icons.admin_panel_settings_rounded,
                        _rootDetection,
                        (v) => setState(() => _rootDetection = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'Integrity Verification',
                        Icons.verified_user_rounded,
                        _integrityCheck,
                        (v) => setState(() => _integrityCheck = v),
                      ),
                      _divider(),
                      _buildToggle(
                        'RASP Engine',
                        Icons.shield_rounded,
                        _raspEngine,
                        (v) => setState(() => _raspEngine = v),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 20),

                // Sliders
                const SectionHeader(title: 'Appearance'),
                const SizedBox(height: 8),
                GlassCard(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      _buildSlider(
                        'Watermark Opacity',
                        _watermarkOpacity,
                        0.05,
                        0.5,
                        (v) => setState(() => _watermarkOpacity = v),
                      ),
                      const SizedBox(height: 16),
                      _buildSlider(
                        'Blur Intensity',
                        _blurSigma,
                        5.0,
                        50.0,
                        (v) => setState(() => _blurSigma = v),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 20),

                // Presets
                const SectionHeader(title: 'Presets'),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Expanded(
                      child: GlassCard(
                        onTap: _applyMaximum,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        child: const Column(
                          children: [
                            Icon(
                              Icons.security_rounded,
                              color: AppTheme.accentGreen,
                              size: 24,
                            ),
                            SizedBox(height: 6),
                            Text(
                              'Maximum',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: AppTheme.accentGreen,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: GlassCard(
                        onTap: _applyMinimum,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        child: const Column(
                          children: [
                            Icon(
                              Icons.tune_rounded,
                              color: AppTheme.warning,
                              size: 24,
                            ),
                            SizedBox(height: 6),
                            Text(
                              'Minimal',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: AppTheme.warning,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),

                const SizedBox(height: 32),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildToggle(
    String label,
    IconData icon,
    bool value,
    ValueChanged<bool> onChanged,
  ) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          Icon(icon, size: 20, color: AppTheme.textSecondary),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(fontSize: 14, color: AppTheme.textPrimary),
            ),
          ),
          Switch.adaptive(
            value: value,
            onChanged: onChanged,
            activeColor: AppTheme.accentGreen,
          ),
        ],
      ),
    );
  }

  Widget _buildSlider(
    String label,
    double value,
    double min,
    double max,
    ValueChanged<double> onChanged,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              label,
              style: const TextStyle(
                fontSize: 13,
                color: AppTheme.textSecondary,
              ),
            ),
            const Spacer(),
            Text(
              value.toStringAsFixed(2),
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: AppTheme.accent,
                fontFeatures: [FontFeature.tabularFigures()],
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        SliderTheme(
          data: SliderThemeData(
            trackHeight: 3,
            thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 7),
            activeTrackColor: AppTheme.primary,
            inactiveTrackColor: Colors.white.withValues(alpha: 0.08),
            thumbColor: AppTheme.primaryLight,
            overlayColor: AppTheme.primary.withValues(alpha: 0.15),
          ),
          child: Slider(value: value, min: min, max: max, onChanged: onChanged),
        ),
      ],
    );
  }

  Widget _divider() {
    return Divider(
      height: 1,
      indent: 48,
      color: Colors.white.withValues(alpha: 0.06),
    );
  }

  void _applyMaximum() {
    setState(() {
      _screenCapturePrevention = true;
      _watermarkOverlay = true;
      _blurOnCapture = true;
      _antiDebug = true;
      _rootDetection = true;
      _integrityCheck = true;
      _raspEngine = true;
      _watermarkOpacity = 0.15;
      _blurSigma = 20.0;
    });
  }

  void _applyMinimum() {
    setState(() {
      _screenCapturePrevention = false;
      _watermarkOverlay = false;
      _blurOnCapture = false;
      _antiDebug = false;
      _rootDetection = false;
      _integrityCheck = false;
      _raspEngine = false;
      _watermarkOpacity = 0.05;
      _blurSigma = 5.0;
    });
  }
}
