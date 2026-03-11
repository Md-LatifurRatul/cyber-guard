import 'package:flutter/material.dart';

import '../../../api/models/media_source.dart';
import '../../../api/models/player_config.dart';
import '../../../api/secure_image_viewer.dart';
import '../../theme/app_theme.dart';
import '../../widgets/glass_card.dart';

/// Demo screen showcasing the secure image gallery.
class ImageGalleryScreen extends StatelessWidget {
  const ImageGalleryScreen({super.key});

  static const _sampleImages = [
    'https://picsum.photos/id/1018/1200/800',
    'https://picsum.photos/id/1015/1200/800',
    'https://picsum.photos/id/1019/1200/800',
    'https://picsum.photos/id/1025/1200/800',
    'https://picsum.photos/id/1035/1200/800',
    'https://picsum.photos/id/1043/1200/800',
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: const Text('Secure Images'),
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
              // Info banner
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 8, 16, 12),
                child: GlassCard(
                  padding: EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        Icons.photo_library_rounded,
                        size: 18,
                        color: AppTheme.primaryLight,
                      ),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Tap an image for fullscreen with pinch-to-zoom & double-tap zoom',
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

              // Image grid
              Expanded(
                child: GridView.builder(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: MediaQuery.of(context).size.width > 600
                        ? 3
                        : 2,
                    mainAxisSpacing: 10,
                    crossAxisSpacing: 10,
                    childAspectRatio: 1.2,
                  ),
                  itemCount: _sampleImages.length,
                  itemBuilder: (context, index) {
                    return GestureDetector(
                      onTap: () => _openGallery(context, index),
                      child: Hero(
                        tag: 'demo_image_$index',
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(14),
                          child: Stack(
                            fit: StackFit.expand,
                            children: [
                              Image.network(
                                _sampleImages[index],
                                fit: BoxFit.cover,
                                loadingBuilder: (_, child, progress) {
                                  if (progress == null) return child;
                                  return Container(
                                    color: AppTheme.surfaceDark,
                                    child: const Center(
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: AppTheme.primary,
                                      ),
                                    ),
                                  );
                                },
                                errorBuilder: (_, _, _) => Container(
                                  color: AppTheme.surfaceDark,
                                  child: const Icon(
                                    Icons.broken_image_rounded,
                                    color: AppTheme.textMuted,
                                  ),
                                ),
                              ),
                              // Gradient overlay at bottom
                              Positioned(
                                bottom: 0,
                                left: 0,
                                right: 0,
                                child: Container(
                                  height: 36,
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      begin: Alignment.topCenter,
                                      end: Alignment.bottomCenter,
                                      colors: [
                                        Colors.transparent,
                                        Colors.black.withValues(alpha: 0.5),
                                      ],
                                    ),
                                  ),
                                  alignment: Alignment.bottomLeft,
                                  padding: const EdgeInsets.only(
                                    left: 8,
                                    bottom: 6,
                                  ),
                                  child: Text(
                                    'Image ${index + 1}',
                                    style: const TextStyle(
                                      fontSize: 11,
                                      color: Colors.white70,
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          ),
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

  void _openGallery(BuildContext context, int initialIndex) {
    Navigator.push(
      context,
      MaterialPageRoute<void>(
        builder: (_) => SecureImageViewer(
          sources: _sampleImages
              .map((url) => ImageSource.network(url))
              .toList(),
          config: ImageViewerConfig(
            initialIndex: initialIndex,
            heroTagPrefix: 'demo_image',
            enableZoom: true,
            maxZoom: 5.0,
          ),
        ),
      ),
    );
  }
}
