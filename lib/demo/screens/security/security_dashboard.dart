import 'dart:async';

import 'package:flutter/material.dart';

import '../../../core/security/security_channel.dart';
import '../../../core/security/security_state.dart';
import '../../theme/app_theme.dart';
import '../../widgets/glass_card.dart';
import '../../widgets/section_header.dart';
import '../../widgets/threat_level_gauge.dart';

/// Real-time security dashboard with threat monitoring.
class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});

  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard> {
  SecurityState _state = const SecurityState();
  StreamSubscription<SecurityState>? _subscription;

  @override
  void initState() {
    super.initState();
    _subscription = SecurityChannel.instance.stateStream.listen((state) {
      if (mounted) setState(() => _state = state);
    });
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }

  double get _threatLevel {
    var score = 0.0;
    if (_state.isScreenBeingCaptured) score += 0.3;
    if (_state.isDeviceRooted) score += 0.25;
    if (_state.isRunningOnEmulator) score += 0.15;
    if (_state.isDebuggerAttached) score += 0.3;
    return score.clamp(0.0, 1.0);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Security Dashboard'),
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
                // Threat gauge
                GlassCard(
                  padding: const EdgeInsets.symmetric(vertical: 24),
                  child: Center(
                    child: ThreatLevelGauge(
                      level: _threatLevel,
                      size: 160,
                    ),
                  ),
                ),

                const SizedBox(height: 20),

                // Active defenses
                const SectionHeader(title: 'Active Defenses'),
                const SizedBox(height: 8),
                _buildDefenseGrid(),

                const SizedBox(height: 20),

                // Device status
                const SectionHeader(title: 'Device Status'),
                const SizedBox(height: 8),
                _buildDeviceStatus(),

                const SizedBox(height: 20),

                // Event log
                const SectionHeader(title: 'Security Events'),
                const SizedBox(height: 8),
                _buildEventLog(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDefenseGrid() {
    final defenses = [
      _Defense('Screen Shield', Icons.screen_lock_portrait_rounded,
          !_state.isScreenBeingCaptured),
      _Defense('Integrity Check', Icons.verified_user_rounded, true),
      _Defense('Anti-Debug', Icons.bug_report_rounded,
          !_state.isDebuggerAttached),
      _Defense('Root Protection', Icons.admin_panel_settings_rounded,
          !_state.isDeviceRooted),
      _Defense('Encryption', Icons.lock_rounded, true),
      _Defense('RASP Engine', Icons.shield_rounded, true),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        mainAxisSpacing: 10,
        crossAxisSpacing: 10,
        childAspectRatio: 1.0,
      ),
      itemCount: defenses.length,
      itemBuilder: (context, index) {
        final d = defenses[index];
        return GlassCard(
          padding: const EdgeInsets.all(10),
          opacity: d.active ? 0.12 : 0.05,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                d.icon,
                size: 24,
                color: d.active ? AppTheme.accentGreen : AppTheme.danger,
              ),
              const SizedBox(height: 8),
              Text(
                d.label,
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.w500,
                  color:
                      d.active ? AppTheme.textPrimary : AppTheme.danger,
                ),
                textAlign: TextAlign.center,
                maxLines: 2,
              ),
              const SizedBox(height: 4),
              Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: d.active ? AppTheme.accentGreen : AppTheme.danger,
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildDeviceStatus() {
    final items = [
      _StatusItem('Screen Capture', _state.isScreenBeingCaptured
          ? 'DETECTED' : 'Clear'),
      _StatusItem('Root/Jailbreak', _state.isDeviceRooted ? 'DETECTED' : 'Clean'),
      _StatusItem('Emulator', _state.isRunningOnEmulator ? 'YES' : 'No'),
      _StatusItem('Debugger', _state.isDebuggerAttached
          ? 'ATTACHED' : 'None'),
      _StatusItem('Secure Mode', _state.isSecureModeActive ? 'Active' : 'Idle'),
    ];

    return GlassCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: items.map((item) {
          final isDanger = item.value == 'DETECTED' ||
              item.value == 'ATTACHED' ||
              item.value == 'YES';
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              children: [
                Text(
                  item.label,
                  style: const TextStyle(
                    fontSize: 13,
                    color: AppTheme.textSecondary,
                  ),
                ),
                const Spacer(),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: (isDanger ? AppTheme.danger : AppTheme.accentGreen)
                        .withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    item.value,
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      color:
                          isDanger ? AppTheme.danger : AppTheme.accentGreen,
                    ),
                  ),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildEventLog() {
    // Show placeholder events for demo
    final events = [
      _EventItem('Security initialized', 'All layers active', Icons.check_circle_rounded, AppTheme.accentGreen),
      _EventItem('Screen capture check', 'No capture detected', Icons.screen_lock_portrait_rounded, AppTheme.accent),
      _EventItem('Integrity verified', 'App binary intact', Icons.verified_rounded, AppTheme.primaryLight),
    ];

    return GlassCard(
      padding: const EdgeInsets.all(14),
      child: Column(
        children: events.asMap().entries.map((entry) {
          final e = entry.value;
          final isLast = entry.key == events.length - 1;
          return Padding(
            padding: EdgeInsets.only(bottom: isLast ? 0 : 12),
            child: Row(
              children: [
                Icon(e.icon, size: 18, color: e.color),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        e.title,
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                          color: AppTheme.textPrimary,
                        ),
                      ),
                      Text(
                        e.subtitle,
                        style: const TextStyle(
                          fontSize: 11,
                          color: AppTheme.textMuted,
                        ),
                      ),
                    ],
                  ),
                ),
                const Text(
                  'now',
                  style: TextStyle(fontSize: 10, color: AppTheme.textMuted),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }
}

class _Defense {
  const _Defense(this.label, this.icon, this.active);
  final String label;
  final IconData icon;
  final bool active;
}

class _StatusItem {
  const _StatusItem(this.label, this.value);
  final String label;
  final String value;
}

class _EventItem {
  const _EventItem(this.title, this.subtitle, this.icon, this.color);
  final String title;
  final String subtitle;
  final IconData icon;
  final Color color;
}
