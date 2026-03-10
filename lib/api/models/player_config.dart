/// Configuration for the secure media player.
///
/// Controls playback behavior, UI appearance, and security integration.
/// All values have sensible defaults — create with `const PlayerConfig()`
/// for standard behavior.
///
/// ## Usage:
/// ```dart
/// CyberGuard.videoPlayer(
///   source: MediaSource.network(url),
///   config: const PlayerConfig(
///     autoPlay: true,
///     looping: true,
///     showControls: true,
///     allowFullscreen: true,
///   ),
/// )
/// ```
class PlayerConfig {
  const PlayerConfig({
    this.autoPlay = false,
    this.looping = false,
    this.showControls = true,
    this.allowFullscreen = true,
    this.allowPictureInPicture = false,
    this.allowBackgroundAudio = false,
    this.allowPlaybackSpeed = true,
    this.initialVolume = 1.0,
    this.initialPlaybackSpeed = 1.0,
    this.controlsAutoHideDelay = const Duration(seconds: 3),
    this.seekDuration = const Duration(seconds: 10),
    this.aspectRatio,
    this.fit = PlayerFit.contain,
    this.placeholder,
    this.errorBuilder,
  });

  /// Start playback immediately when the player is ready.
  final bool autoPlay;

  /// Loop playback when the media ends.
  final bool looping;

  /// Show the built-in player controls overlay.
  /// Set to false to build your own controls using [SecurePlayerController].
  final bool showControls;

  /// Allow the user to enter fullscreen mode.
  final bool allowFullscreen;

  /// Allow Picture-in-Picture mode (platform-dependent).
  final bool allowPictureInPicture;

  /// Allow audio to continue when the app is backgrounded.
  /// Note: content protection (blur) still activates on background.
  final bool allowBackgroundAudio;

  /// Show playback speed selector in controls.
  final bool allowPlaybackSpeed;

  /// Initial volume (0.0 = muted, 1.0 = full).
  final double initialVolume;

  /// Initial playback speed (1.0 = normal).
  /// Common values: 0.5, 0.75, 1.0, 1.25, 1.5, 2.0
  final double initialPlaybackSpeed;

  /// How long to wait before auto-hiding controls after last interaction.
  final Duration controlsAutoHideDelay;

  /// How far to seek on double-tap left/right.
  final Duration seekDuration;

  /// Override the content's natural aspect ratio.
  /// If null, the player uses the media's intrinsic aspect ratio.
  final double? aspectRatio;

  /// How the video fits within the player bounds.
  final PlayerFit fit;

  /// Widget shown while the media is loading.
  /// If null, a default loading indicator is shown.
  final PlayerPlaceholderBuilder? placeholder;

  /// Widget shown when an error occurs.
  /// If null, a default error message is shown.
  final PlayerErrorBuilder? errorBuilder;

  /// Maximum protection preset — autoplay off, no PiP, no background audio.
  static const PlayerConfig secure = PlayerConfig(
    allowPictureInPicture: false,
    allowBackgroundAudio: false,
  );
}

/// How the video content fits within the player widget bounds.
enum PlayerFit {
  /// Scale to fit within bounds, preserving aspect ratio (letterbox/pillarbox).
  contain,

  /// Scale to fill bounds, preserving aspect ratio (may crop edges).
  cover,

  /// Stretch to fill bounds exactly (may distort).
  fill,
}

/// Builder for custom loading placeholder.
typedef PlayerPlaceholderBuilder = Object Function();

/// Builder for custom error display.
typedef PlayerErrorBuilder = Object Function(String error);

/// Configuration for the secure PDF viewer.
///
/// ## Usage:
/// ```dart
/// CyberGuard.pdfViewer(
///   source: PdfSource.network(url),
///   config: const PdfViewerConfig(
///     showThumbnails: true,
///     enableSearch: true,
///     enableNightMode: false,
///   ),
/// )
/// ```
class PdfViewerConfig {
  const PdfViewerConfig({
    this.showToolbar = true,
    this.showThumbnails = true,
    this.showPageNumber = true,
    this.enableSearch = true,
    this.enableNightMode = false,
    this.enableZoom = true,
    this.initialPage = 0,
    this.maxZoom = 4.0,
    this.pageCacheExtent = 2,
    this.scrollDirection = PdfScrollDirection.horizontal,
  });

  /// Show the top toolbar (page number, search, night mode toggle).
  final bool showToolbar;

  /// Show the thumbnail strip for quick page navigation.
  final bool showThumbnails;

  /// Show the current page / total pages indicator.
  final bool showPageNumber;

  /// Enable text search within the PDF.
  final bool enableSearch;

  /// Start in night mode (inverted colors for dark reading).
  final bool enableNightMode;

  /// Allow pinch-to-zoom on pages.
  final bool enableZoom;

  /// Initial page index (0-based).
  final int initialPage;

  /// Maximum zoom factor (1.0 = no zoom, 4.0 = 4x magnification).
  final double maxZoom;

  /// Number of pages to pre-render ahead/behind the current page.
  /// Higher values use more memory but give smoother scrolling.
  final int pageCacheExtent;

  /// Scroll direction for page navigation.
  final PdfScrollDirection scrollDirection;
}

/// Scroll direction for PDF page navigation.
enum PdfScrollDirection {
  /// Swipe left/right to change pages.
  horizontal,

  /// Scroll up/down continuously.
  vertical,
}

/// Configuration for the secure image viewer/gallery.
///
/// ## Usage:
/// ```dart
/// CyberGuard.imageViewer(
///   sources: images,
///   config: const ImageViewerConfig(
///     enableZoom: true,
///     maxZoom: 5.0,
///     showPageIndicator: true,
///   ),
/// )
/// ```
class ImageViewerConfig {
  const ImageViewerConfig({
    this.enableZoom = true,
    this.maxZoom = 5.0,
    this.minZoom = 1.0,
    this.doubleTapZoom = 2.0,
    this.enableSwipe = true,
    this.showPageIndicator = true,
    this.showCloseButton = true,
    this.backgroundColor,
    this.initialIndex = 0,
    this.heroTagPrefix,
    this.imageCacheSize = 50,
  });

  /// Allow pinch-to-zoom and double-tap zoom on images.
  final bool enableZoom;

  /// Maximum zoom factor.
  final double maxZoom;

  /// Minimum zoom factor (1.0 = original size).
  final double minZoom;

  /// Zoom level on double-tap (must be between minZoom and maxZoom).
  final double doubleTapZoom;

  /// Allow swiping between images in gallery mode.
  final bool enableSwipe;

  /// Show dot indicator or page number for multi-image galleries.
  final bool showPageIndicator;

  /// Show an X button to close the viewer.
  final bool showCloseButton;

  /// Background color behind the image. Defaults to black.
  final int? backgroundColor;

  /// Initial image index in gallery mode (0-based).
  final int initialIndex;

  /// Prefix for Hero animation tags.
  /// If set, enables Hero transitions from thumbnails to fullscreen.
  /// Each image gets tag: '{prefix}_{index}'.
  final String? heroTagPrefix;

  /// Maximum number of images to keep in memory cache.
  final int imageCacheSize;
}
