import 'package:flutter/material.dart';

import '../ui/secure_content_widget.dart';
import '../viewers/image/cached_secure_image.dart';
import 'models/media_source.dart';
import 'models/player_config.dart';

/// Protected image viewer/gallery with full CyberGuard security.
///
/// Supports single image viewing and multi-image gallery mode with
/// pinch-to-zoom, double-tap zoom, pan, and swipe navigation.
/// All wrapped in CyberGuard's security layers.
///
/// ## Features:
/// - Pinch-to-zoom (up to 5x) with smooth physics
/// - Double-tap to toggle zoom with animated transition
/// - Pan when zoomed in (bounded to image edges)
/// - Swipe between images in gallery mode
/// - Hero animation from thumbnail to fullscreen
/// - Loading shimmer + error state
/// - LRU cached network images via [CachedSecureImage]
/// - Network, asset, file, and memory image sources
///
/// ## Usage:
/// ```dart
/// // Single image
/// SecureImageViewer(
///   sources: [ImageSource.network('https://cdn.example.com/photo.jpg')],
/// )
///
/// // Gallery with multiple images
/// SecureImageViewer(
///   sources: [
///     ImageSource.network('https://cdn.example.com/1.jpg'),
///     ImageSource.network('https://cdn.example.com/2.jpg'),
///     ImageSource.asset('assets/images/3.png'),
///   ],
///   config: const ImageViewerConfig(
///     initialIndex: 0,
///     enableZoom: true,
///   ),
/// )
/// ```
class SecureImageViewer extends StatefulWidget {
  const SecureImageViewer({
    super.key,
    required this.sources,
    this.config = const ImageViewerConfig(),
    this.onPageChanged,
    this.onError,
  });

  /// Image sources to display. Single item = single viewer, multiple = gallery.
  final List<ImageSource> sources;

  /// Viewer configuration (zoom, swipe, indicators, etc.).
  final ImageViewerConfig config;

  /// Called when the user swipes to a different image in gallery mode.
  final void Function(int index)? onPageChanged;

  /// Called when an image fails to load.
  final void Function(int index, String error)? onError;

  @override
  State<SecureImageViewer> createState() => _SecureImageViewerState();
}

class _SecureImageViewerState extends State<SecureImageViewer> {
  late int _currentIndex;
  late final PageController _pageController;

  bool get _isGallery => widget.sources.length > 1;

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.config.initialIndex.clamp(
      0,
      widget.sources.length - 1,
    );
    _pageController = PageController(initialPage: _currentIndex);

    // Configure image cache size
    SecureImageCache.instance.maxSize = widget.config.imageCacheSize;
  }

  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SecureContentWidget(
      child: Container(
        color: widget.config.backgroundColor != null
            ? Color(widget.config.backgroundColor!)
            : Colors.black,
        child: Stack(
          children: [
            // Image content
            if (_isGallery)
              PageView.builder(
                controller: _pageController,
                itemCount: widget.sources.length,
                onPageChanged: (index) {
                  setState(() => _currentIndex = index);
                  widget.onPageChanged?.call(index);
                },
                physics: widget.config.enableSwipe
                    ? const BouncingScrollPhysics()
                    : const NeverScrollableScrollPhysics(),
                itemBuilder: (context, index) =>
                    _buildImagePage(widget.sources[index], index),
              )
            else
              _buildImagePage(widget.sources.first, 0),

            // Page indicator
            if (_isGallery && widget.config.showPageIndicator)
              Positioned(
                bottom: 24,
                left: 0,
                right: 0,
                child: _PageIndicator(
                  currentIndex: _currentIndex,
                  totalCount: widget.sources.length,
                ),
              ),

            // Close button
            if (widget.config.showCloseButton)
              Positioned(
                top: MediaQuery.of(context).padding.top + 8,
                right: 8,
                child: IconButton(
                  onPressed: () => Navigator.maybePop(context),
                  icon: const Icon(Icons.close),
                  color: Colors.white,
                  style: IconButton.styleFrom(
                    backgroundColor: Colors.black38,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildImagePage(ImageSource source, int index) {
    final imageWidget = CachedSecureImage(
      source: source,
      fit: BoxFit.contain,
      errorWidget: _errorWidget(index),
    );
    final tag = widget.config.heroTagPrefix;

    final Widget content;
    if (widget.config.enableZoom) {
      content = _DoubleTapZoomViewer(
        minScale: widget.config.minZoom,
        maxScale: widget.config.maxZoom,
        doubleTapScale: widget.config.doubleTapZoom,
        child: Center(child: imageWidget),
      );
    } else {
      content = Center(child: imageWidget);
    }

    if (tag != null) {
      return Hero(tag: '${tag}_$index', child: content);
    }

    return content;
  }

  Widget _errorWidget(int index) {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.broken_image_rounded, size: 48, color: Colors.white38),
          SizedBox(height: 8),
          Text(
            'Failed to load image',
            style: TextStyle(color: Colors.white54, fontSize: 14),
          ),
        ],
      ),
    );
  }
}

/// Interactive viewer with animated double-tap zoom toggle.
///
/// Double-tapping zooms to [doubleTapScale] centered on the tap point.
/// Double-tapping again resets to 1.0 (fit). Also supports pinch-to-zoom.
class _DoubleTapZoomViewer extends StatefulWidget {
  const _DoubleTapZoomViewer({
    required this.minScale,
    required this.maxScale,
    required this.doubleTapScale,
    required this.child,
  });

  final double minScale;
  final double maxScale;
  final double doubleTapScale;
  final Widget child;

  @override
  State<_DoubleTapZoomViewer> createState() => _DoubleTapZoomViewerState();
}

class _DoubleTapZoomViewerState extends State<_DoubleTapZoomViewer>
    with SingleTickerProviderStateMixin {
  final _transformController = TransformationController();
  late final AnimationController _animController;
  Animation<Matrix4>? _animation;
  TapDownDetails? _doubleTapDetails;

  @override
  void initState() {
    super.initState();
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 250),
    )..addListener(() {
        if (_animation != null) {
          _transformController.value = _animation!.value;
        }
      });
  }

  @override
  void dispose() {
    _animController.dispose();
    _transformController.dispose();
    super.dispose();
  }

  void _handleDoubleTapDown(TapDownDetails details) {
    _doubleTapDetails = details;
  }

  void _handleDoubleTap() {
    final position = _doubleTapDetails?.localPosition;
    if (position == null) return;

    final currentScale = _transformController.value.getMaxScaleOnAxis();
    final isZoomed = currentScale > 1.05;

    final Matrix4 target;
    if (isZoomed) {
      // Zoom out to fit
      target = Matrix4.identity();
    } else {
      // Zoom in to doubleTapScale, centered on tap point
      final scale = widget.doubleTapScale;
      final dx = (1 - scale) * position.dx;
      final dy = (1 - scale) * position.dy;
      target = Matrix4.identity()
        ..translateByDouble(dx, dy, 0, 0)
        ..scaleByDouble(scale, scale, 1, 1);
    }

    _animation = Matrix4Tween(
      begin: _transformController.value,
      end: target,
    ).animate(CurvedAnimation(
      parent: _animController,
      curve: Curves.easeInOut,
    ));

    _animController.forward(from: 0);
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onDoubleTapDown: _handleDoubleTapDown,
      onDoubleTap: _handleDoubleTap,
      child: InteractiveViewer(
        transformationController: _transformController,
        minScale: widget.minScale,
        maxScale: widget.maxScale,
        child: widget.child,
      ),
    );
  }
}

/// Dot indicator for gallery page position.
class _PageIndicator extends StatelessWidget {
  const _PageIndicator({
    required this.currentIndex,
    required this.totalCount,
  });

  final int currentIndex;
  final int totalCount;

  @override
  Widget build(BuildContext context) {
    // For large galleries, show numeric indicator instead of dots
    if (totalCount > 10) {
      return Center(
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: Colors.black45,
            borderRadius: BorderRadius.circular(16),
          ),
          child: Text(
            '${currentIndex + 1} / $totalCount',
            style: const TextStyle(color: Colors.white, fontSize: 13),
          ),
        ),
      );
    }

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(totalCount, (index) {
        final isActive = index == currentIndex;
        return AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          margin: const EdgeInsets.symmetric(horizontal: 3),
          width: isActive ? 24 : 8,
          height: 8,
          decoration: BoxDecoration(
            color: isActive ? Colors.white : Colors.white38,
            borderRadius: BorderRadius.circular(4),
          ),
        );
      }),
    );
  }
}
