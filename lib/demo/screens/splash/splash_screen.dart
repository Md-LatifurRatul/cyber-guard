import 'package:flutter/material.dart';

import '../../theme/app_theme.dart';
import '../../widgets/animated_shield.dart';

/// Animated splash screen with security initialization sequence.
///
/// Shows the CyberGuard shield logo with a pulse animation,
/// followed by security check items appearing sequentially.
/// Auto-navigates to [onComplete] after all checks finish.
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key, required this.onComplete});

  final VoidCallback onComplete;

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with TickerProviderStateMixin {
  late final AnimationController _fadeController;
  late final AnimationController _checksController;
  late final Animation<double> _fadeAnimation;

  final _checks = const <_SecurityCheck>[
    _SecurityCheck('Platform Security', Icons.verified_user_rounded),
    _SecurityCheck('Screen Capture Shield', Icons.screen_lock_portrait_rounded),
    _SecurityCheck('Integrity Verification', Icons.fingerprint_rounded),
    _SecurityCheck('Encryption Engine', Icons.lock_rounded),
    _SecurityCheck('RASP Protection', Icons.shield_rounded),
  ];

  int _visibleChecks = 0;

  @override
  void initState() {
    super.initState();

    _fadeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 800),
    );
    _fadeAnimation = CurvedAnimation(
      parent: _fadeController,
      curve: Curves.easeOut,
    );

    _checksController = AnimationController(
      vsync: this,
      duration: Duration(milliseconds: _checks.length * 350 + 400),
    );

    _fadeController.forward();
    _startCheckSequence();
  }

  Future<void> _startCheckSequence() async {
    await Future<void>.delayed(const Duration(milliseconds: 1000));
    if (!mounted) return;

    for (var i = 0; i < _checks.length; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 350));
      if (!mounted) return;
      setState(() => _visibleChecks = i + 1);
    }

    await Future<void>.delayed(const Duration(milliseconds: 600));
    if (!mounted) return;
    widget.onComplete();
  }

  @override
  void dispose() {
    _fadeController.dispose();
    _checksController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(gradient: AppTheme.backgroundGradient),
        child: SafeArea(
          child: FadeTransition(
            opacity: _fadeAnimation,
            child: Column(
              children: [
                const Spacer(flex: 2),

                // Shield logo
                const AnimatedShield(size: 100),
                const SizedBox(height: 24),

                // Title
                const Text(
                  'CYBERGUARD',
                  style: TextStyle(
                    fontSize: 26,
                    fontWeight: FontWeight.w700,
                    color: AppTheme.textPrimary,
                    letterSpacing: 4,
                  ),
                ),
                const SizedBox(height: 6),
                const Text(
                  'Defense-in-Depth Protection',
                  style: TextStyle(
                    fontSize: 13,
                    color: AppTheme.textMuted,
                    letterSpacing: 1,
                  ),
                ),

                const Spacer(),

                // Security checks
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 48),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Initializing security...',
                        style: TextStyle(
                          fontSize: 12,
                          color: AppTheme.textMuted,
                          letterSpacing: 0.5,
                        ),
                      ),
                      const SizedBox(height: 16),
                      ..._checks.asMap().entries.map((entry) {
                        final index = entry.key;
                        final check = entry.value;
                        final visible = index < _visibleChecks;
                        return _CheckItem(
                          check: check,
                          visible: visible,
                        );
                      }),
                    ],
                  ),
                ),

                const Spacer(flex: 2),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SecurityCheck {
  const _SecurityCheck(this.label, this.icon);
  final String label;
  final IconData icon;
}

class _CheckItem extends StatelessWidget {
  const _CheckItem({required this.check, required this.visible});

  final _SecurityCheck check;
  final bool visible;

  @override
  Widget build(BuildContext context) {
    return AnimatedOpacity(
      opacity: visible ? 1.0 : 0.0,
      duration: AppTheme.splashCheck,
      curve: Curves.easeOut,
      child: AnimatedSlide(
        offset: visible ? Offset.zero : const Offset(0.1, 0),
        duration: AppTheme.splashCheck,
        curve: Curves.easeOut,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            children: [
              Icon(
                visible ? Icons.check_circle_rounded : check.icon,
                size: 18,
                color: visible ? AppTheme.accentGreen : AppTheme.textMuted,
              ),
              const SizedBox(width: 12),
              Text(
                check.label,
                style: TextStyle(
                  fontSize: 13,
                  color: visible
                      ? AppTheme.textPrimary
                      : AppTheme.textMuted,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
