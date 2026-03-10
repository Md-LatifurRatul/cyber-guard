import 'package:flutter/material.dart';

import '../../theme/app_theme.dart';
import '../../widgets/feature_card.dart';
import '../../widgets/section_header.dart';
import '../image/image_gallery_screen.dart';
import '../pdf/pdf_demo_screen.dart';
import '../security/security_dashboard.dart';
import '../settings/config_screen.dart';
import '../video/video_demo_screen.dart';

/// Home screen with glassmorphic feature grid.
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(gradient: AppTheme.backgroundGradient),
        child: SafeArea(
          child: CustomScrollView(
            slivers: [
              // Header
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 16, 20, 8),
                  child: Row(
                    children: [
                      Container(
                        width: 36,
                        height: 36,
                        decoration: BoxDecoration(
                          gradient: AppTheme.shieldGradient,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: const Icon(
                          Icons.shield_rounded,
                          size: 20,
                          color: Colors.white,
                        ),
                      ),
                      const SizedBox(width: 12),
                      const Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'CyberGuard',
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.w700,
                              color: AppTheme.textPrimary,
                              letterSpacing: 0.5,
                            ),
                          ),
                          Text(
                            'Defense-in-Depth Framework',
                            style: TextStyle(
                              fontSize: 11,
                              color: AppTheme.textMuted,
                            ),
                          ),
                        ],
                      ),
                      const Spacer(),
                      _StatusChip(),
                    ],
                  ),
                ),
              ),

              // Content viewers section
              const SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.fromLTRB(20, 20, 20, 8),
                  child: SectionHeader(title: 'Protected Viewers'),
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverGrid.count(
                  crossAxisCount:
                      MediaQuery.of(context).size.width > 600 ? 3 : 2,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.1,
                  children: [
                    FeatureCard(
                      icon: Icons.play_circle_rounded,
                      title: 'Secure Video',
                      subtitle: 'Protected playback',
                      iconColor: AppTheme.accent,
                      badge: 'LIVE',
                      onTap: () => _push(context, const VideoDemoScreen()),
                    ),
                    FeatureCard(
                      icon: Icons.picture_as_pdf_rounded,
                      title: 'Secure PDF',
                      subtitle: 'Document viewer',
                      iconColor: Colors.redAccent,
                      onTap: () => _push(context, const PdfDemoScreen()),
                    ),
                    FeatureCard(
                      icon: Icons.photo_library_rounded,
                      title: 'Secure Images',
                      subtitle: 'Image gallery',
                      iconColor: AppTheme.primaryLight,
                      onTap: () =>
                          _push(context, const ImageGalleryScreen()),
                    ),
                  ],
                ),
              ),

              // Security tools section
              const SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.fromLTRB(20, 24, 20, 8),
                  child: SectionHeader(title: 'Security Tools'),
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverGrid.count(
                  crossAxisCount:
                      MediaQuery.of(context).size.width > 600 ? 3 : 2,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.1,
                  children: [
                    FeatureCard(
                      icon: Icons.dashboard_rounded,
                      title: 'Dashboard',
                      subtitle: 'Threat monitor',
                      iconColor: AppTheme.warning,
                      onTap: () =>
                          _push(context, const SecurityDashboard()),
                    ),
                    FeatureCard(
                      icon: Icons.settings_rounded,
                      title: 'Settings',
                      subtitle: 'Configuration',
                      iconColor: AppTheme.textSecondary,
                      onTap: () => _push(context, const ConfigScreen()),
                    ),
                  ],
                ),
              ),

              // Bottom padding
              const SliverToBoxAdapter(child: SizedBox(height: 32)),
            ],
          ),
        ),
      ),
    );
  }

  void _push(BuildContext context, Widget screen) {
    Navigator.push(
      context,
      PageRouteBuilder<void>(
        pageBuilder: (_, animation, _) => screen,
        transitionsBuilder: (_, animation, _, child) {
          return FadeTransition(
            opacity: CurvedAnimation(
              parent: animation,
              curve: AppTheme.defaultCurve,
            ),
            child: SlideTransition(
              position: Tween<Offset>(
                begin: const Offset(0.05, 0),
                end: Offset.zero,
              ).animate(CurvedAnimation(
                parent: animation,
                curve: AppTheme.defaultCurve,
              )),
              child: child,
            ),
          );
        },
        transitionDuration: AppTheme.pageTransition,
      ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: AppTheme.accentGreen.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: AppTheme.accentGreen.withValues(alpha: 0.3),
        ),
      ),
      child: const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.check_circle, size: 14, color: AppTheme.accentGreen),
          SizedBox(width: 5),
          Text(
            'SECURE',
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: AppTheme.accentGreen,
              letterSpacing: 1,
            ),
          ),
        ],
      ),
    );
  }
}
