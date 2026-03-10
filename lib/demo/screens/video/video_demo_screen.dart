import 'package:flutter/material.dart';

import '../../../api/models/media_source.dart';
import '../../../api/models/player_config.dart';
import '../../../api/secure_media_player.dart';
import '../../theme/app_theme.dart';
import '../../widgets/glass_card.dart';
import '../../widgets/section_header.dart';

/// Demo screen showcasing the secure video player.
class VideoDemoScreen extends StatefulWidget {
  const VideoDemoScreen({super.key});

  @override
  State<VideoDemoScreen> createState() => _VideoDemoScreenState();
}

class _VideoDemoScreenState extends State<VideoDemoScreen> {
  int _selectedIndex = 0;

  static const _samples = <_VideoSample>[
    _VideoSample(
      title: 'Big Buck Bunny (MP4)',
      subtitle: 'H.264, 1080p',
      url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4',
      icon: Icons.movie_rounded,
    ),
    _VideoSample(
      title: 'Elephant Dream (MP4)',
      subtitle: 'H.264, 480p',
      url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4',
      icon: Icons.movie_rounded,
    ),
    _VideoSample(
      title: 'Sintel (MP4)',
      subtitle: 'H.264, 720p',
      url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4',
      icon: Icons.movie_rounded,
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final sample = _samples[_selectedIndex];

    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Secure Video'),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_rounded, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Container(
        decoration: const BoxDecoration(gradient: AppTheme.backgroundGradient),
        child: SafeArea(
          child: Column(
            children: [
              // Player
              AspectRatio(
                aspectRatio: 16 / 9,
                child: SecureMediaPlayer(
                  key: ValueKey(sample.url),
                  source: MediaSource.network(sample.url),
                  config: const PlayerConfig(
                    autoPlay: true,
                    showControls: true,
                  ),
                ),
              ),

              const SizedBox(height: 16),

              // Info banner
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: GlassCard(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        Icons.shield_rounded,
                        size: 18,
                        color: AppTheme.accentGreen,
                      ),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'Content protected by watermark + screen capture prevention',
                          style: TextStyle(
                            fontSize: 12,
                            color: AppTheme.textSecondary,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 16),

              // Sample selector
              const Padding(
                padding: EdgeInsets.symmetric(horizontal: 16),
                child: SectionHeader(title: 'Sample Content'),
              ),
              const SizedBox(height: 8),

              Expanded(
                child: ListView.builder(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  itemCount: _samples.length,
                  itemBuilder: (context, index) {
                    final item = _samples[index];
                    final isSelected = index == _selectedIndex;
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: GlassCard(
                        padding: const EdgeInsets.all(14),
                        opacity: isSelected ? 0.15 : 0.08,
                        onTap: () => setState(() => _selectedIndex = index),
                        child: Row(
                          children: [
                            Container(
                              width: 36,
                              height: 36,
                              decoration: BoxDecoration(
                                color: (isSelected
                                        ? AppTheme.accent
                                        : AppTheme.textMuted)
                                    .withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Icon(
                                item.icon,
                                size: 18,
                                color: isSelected
                                    ? AppTheme.accent
                                    : AppTheme.textMuted,
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    item.title,
                                    style: TextStyle(
                                      fontSize: 14,
                                      fontWeight: FontWeight.w500,
                                      color: isSelected
                                          ? AppTheme.textPrimary
                                          : AppTheme.textSecondary,
                                    ),
                                  ),
                                  Text(
                                    item.subtitle,
                                    style: const TextStyle(
                                      fontSize: 11,
                                      color: AppTheme.textMuted,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            if (isSelected)
                              const Icon(
                                Icons.play_circle_filled_rounded,
                                color: AppTheme.accent,
                                size: 24,
                              ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _VideoSample {
  const _VideoSample({
    required this.title,
    required this.subtitle,
    required this.url,
    required this.icon,
  });

  final String title;
  final String subtitle;
  final String url;
  final IconData icon;
}
