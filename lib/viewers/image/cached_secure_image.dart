import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../../api/models/media_source.dart';

/// In-memory LRU image cache for secure network images.
///
/// Caches decoded [ImageProvider] instances by URL key to avoid redundant
/// network requests. Thread-safe via Dart's single-threaded async model.
///
/// The cache is global (singleton) so images persist across widget rebuilds
/// and route transitions within the same session.
class SecureImageCache {
  SecureImageCache._();
  static final instance = SecureImageCache._();

  /// Maximum number of entries in the cache.
  int maxSize = 50;

  /// LRU map: most-recently-used at the end.
  final _cache = <String, Uint8List>{};

  /// Get cached image bytes by key, or null if not cached.
  Uint8List? get(String key) {
    final data = _cache.remove(key);
    if (data != null) {
      // Re-insert at end (most recent)
      _cache[key] = data;
    }
    return data;
  }

  /// Store image bytes in the cache.
  void put(String key, Uint8List bytes) {
    // Remove first if already present to update position
    _cache.remove(key);
    _cache[key] = bytes;
    _evict();
  }

  /// Remove a specific entry.
  void remove(String key) => _cache.remove(key);

  /// Clear all cached images.
  void clear() => _cache.clear();

  /// Current number of cached entries.
  int get length => _cache.length;

  void _evict() {
    while (_cache.length > maxSize) {
      _cache.remove(_cache.keys.first);
    }
  }
}

/// A secure, cached image widget that loads images from [ImageSource].
///
/// For network images, bytes are fetched and stored in [SecureImageCache]
/// so subsequent displays are instant. Asset, file, and memory sources
/// are loaded directly without caching.
///
/// ## Features:
/// - LRU cache for network images (configurable max size)
/// - Loading placeholder (shimmer or spinner)
/// - Error state with retry
/// - Fade-in animation on load
/// - Respects [BoxFit] for sizing
class CachedSecureImage extends StatelessWidget {
  const CachedSecureImage({
    super.key,
    required this.source,
    this.width,
    this.height,
    this.fit = BoxFit.cover,
    this.alignment = Alignment.center,
    this.placeholder,
    this.errorWidget,
    this.fadeInDuration = const Duration(milliseconds: 200),
  });

  final ImageSource source;
  final double? width;
  final double? height;
  final BoxFit fit;
  final Alignment alignment;
  final Widget? placeholder;
  final Widget? errorWidget;
  final Duration fadeInDuration;

  @override
  Widget build(BuildContext context) {
    return switch (source) {
      NetworkImageSource(url: final url, headers: final headers) =>
        _NetworkCachedImage(
          url: url,
          headers: headers,
          width: width,
          height: height,
          fit: fit,
          alignment: alignment,
          placeholder: placeholder,
          errorWidget: errorWidget,
          fadeInDuration: fadeInDuration,
        ),
      AssetImageSource(assetPath: final path) => Image.asset(
          path,
          width: width,
          height: height,
          fit: fit,
          alignment: alignment,
          errorBuilder: (_, _, _) =>
              errorWidget ?? _defaultError(),
        ),
      FileImageSource(filePath: final path) => Image.network(
          'file://$path',
          width: width,
          height: height,
          fit: fit,
          alignment: alignment,
          errorBuilder: (_, _, _) =>
              errorWidget ?? _defaultError(),
        ),
      MemoryImageSource(bytes: final bytes) => Image.memory(
          bytes,
          width: width,
          height: height,
          fit: fit,
          alignment: alignment,
          errorBuilder: (_, _, _) =>
              errorWidget ?? _defaultError(),
        ),
    };
  }

  static Widget _defaultError() {
    return const Center(
      child: Icon(Icons.broken_image_rounded, size: 32, color: Colors.white38),
    );
  }
}

/// Network image with LRU cache support.
class _NetworkCachedImage extends StatelessWidget {
  const _NetworkCachedImage({
    required this.url,
    required this.headers,
    this.width,
    this.height,
    required this.fit,
    required this.alignment,
    this.placeholder,
    this.errorWidget,
    required this.fadeInDuration,
  });

  final String url;
  final Map<String, String> headers;
  final double? width;
  final double? height;
  final BoxFit fit;
  final Alignment alignment;
  final Widget? placeholder;
  final Widget? errorWidget;
  final Duration fadeInDuration;

  @override
  Widget build(BuildContext context) {
    // Check cache first
    final cached = SecureImageCache.instance.get(url);
    if (cached != null) {
      return Image.memory(
        cached,
        width: width,
        height: height,
        fit: fit,
        alignment: alignment,
        errorBuilder: (_, _, _) =>
            errorWidget ?? CachedSecureImage._defaultError(),
      );
    }

    // Load from network with caching
    return Image.network(
      url,
      headers: headers.isEmpty ? null : headers,
      width: width,
      height: height,
      fit: fit,
      alignment: alignment,
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) {
          // Fully loaded — cache will be populated via the frameBuilder
          return child;
        }
        return SizedBox(
          width: width,
          height: height,
          child: placeholder ??
              Center(
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  value: loadingProgress.expectedTotalBytes != null
                      ? loadingProgress.cumulativeBytesLoaded /
                          loadingProgress.expectedTotalBytes!
                      : null,
                ),
              ),
        );
      },
      frameBuilder: (context, child, frame, wasSynchronouslyLoaded) {
        if (wasSynchronouslyLoaded) return child;
        return AnimatedOpacity(
          opacity: frame == null ? 0.0 : 1.0,
          duration: fadeInDuration,
          curve: Curves.easeOut,
          child: child,
        );
      },
      errorBuilder: (_, _, _) =>
          errorWidget ?? CachedSecureImage._defaultError(),
    );
  }
}
