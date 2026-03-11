import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../media/player_controls.dart';
import '../media/player_overlay.dart';
import '../media/player_state.dart';
import '../media/secure_player_controller.dart';
import '../platform/web_video_stub.dart'
    if (dart.library.js_interop) '../platform/web_video_web.dart'
    as web_video;
import '../ui/secure_content_widget.dart';
import 'models/media_source.dart';
import 'models/player_config.dart';

/// Protected video/audio player with full CyberGuard security.
///
/// Wraps platform-native media playback (ExoPlayer on Android, AVPlayer
/// on iOS/macOS, HTML5 `<video>` on web) with all security layers:
/// watermark, blur shield, screen capture prevention, and RASP monitoring.
///
/// ## Supported formats:
/// - **Video:** MP4, 3GP, WebM, MKV, MOV, AVI, FLV
/// - **Streaming:** HLS (.m3u8), DASH (.mpd), RTMP (live)
/// - **Audio:** MP3, AAC, OGG, FLAC, WAV
///
/// ## Usage:
/// ```dart
/// SecureMediaPlayer(
///   source: MediaSource.network('https://example.com/video.mp4'),
///   config: const PlayerConfig(autoPlay: true, showControls: true),
/// )
/// ```
///
/// ## Architecture:
/// ```
/// SecureMediaPlayer
///   └── SecureContentWidget (watermark + blur + FLAG_SECURE)
///         └── Stack
///               ├── Texture(textureId)     ← native video frames
///               │   OR HtmlElementView     ← web video element
///               ├── PlayerOverlay          ← buffering/error/completed
///               └── PlayerControls         ← interactive controls
/// ```
class SecureMediaPlayer extends StatefulWidget {
  const SecureMediaPlayer({
    super.key,
    required this.source,
    this.config = const PlayerConfig(),
    this.onReady,
    this.onCompleted,
    this.onError,
  });

  /// Media source (network URL, asset, file, live stream, or memory bytes).
  final MediaSource source;

  /// Player configuration (autoplay, controls, fullscreen, etc.).
  final PlayerConfig config;

  /// Called when the player is initialized and ready to play.
  final VoidCallback? onReady;

  /// Called when playback reaches the end of the media.
  final VoidCallback? onCompleted;

  /// Called when a playback error occurs.
  final void Function(String error)? onError;

  @override
  State<SecureMediaPlayer> createState() => _SecureMediaPlayerState();
}

class _SecureMediaPlayerState extends State<SecureMediaPlayer> {
  late SecurePlayerController _controller;

  @override
  void initState() {
    super.initState();
    _controller = SecurePlayerController(
      source: widget.source,
      config: widget.config,
    );
    _controller.addListener(_onStateChanged);
    _controller.initialize();
  }

  @override
  void dispose() {
    _controller.removeListener(_onStateChanged);
    _controller.dispose();
    super.dispose();
  }

  void _onStateChanged() {
    final state = _controller.state;

    // Forward lifecycle events to widget callbacks
    if (state.status == PlayerStatus.ready) {
      widget.onReady?.call();
    } else if (state.status == PlayerStatus.completed) {
      widget.onCompleted?.call();
    } else if (state.status == PlayerStatus.error) {
      widget.onError?.call(state.errorMessage ?? 'Unknown error');
    }
  }

  @override
  Widget build(BuildContext context) {
    return SecureContentWidget(
      child: ListenableBuilder(
        listenable: _controller,
        builder: (context, _) {
          final state = _controller.state;
          final aspectRatio =
              widget.config.aspectRatio ?? state.aspectRatio;

          return AspectRatio(
            aspectRatio: aspectRatio,
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Container(
                color: Colors.black,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    // Video surface: web uses HTML video, native uses Texture
                    if (kIsWeb && _controller.isWebPlayer)
                      Positioned.fill(
                        child: _buildWebVideoSurface(),
                      )
                    else if (state.textureId != null)
                      Positioned.fill(
                        child: _buildVideoSurface(state),
                      )
                    else
                      _buildPlaceholder(),

                    // Overlay states (buffering, error, completed)
                    Positioned.fill(
                      child: PlayerOverlay(
                        controller: _controller,
                        onRetry: () => _controller.initialize(),
                      ),
                    ),

                    // Interactive controls
                    if (widget.config.showControls)
                      Positioned.fill(
                        child: PlayerControls(
                          controller: _controller,
                          config: widget.config,
                        ),
                      ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  /// Build an HTML5 video element for web playback.
  Widget _buildWebVideoSurface() {
    final url = _controller.resolvedUrl;
    if (url == null) return _buildPlaceholder();

    return web_video.createWebVideoElement(
      url: url,
      elementId: _controller.webElementId!,
      autoPlay: widget.config.autoPlay,
      volume: widget.config.initialVolume,
    );
  }

  Widget _buildVideoSurface(PlayerState state) {
    final texture = Texture(textureId: state.textureId!);

    // Apply fit mode
    return switch (widget.config.fit) {
      PlayerFit.contain => FittedBox(
          fit: BoxFit.contain,
          child: SizedBox(
            width: state.videoWidth > 0 ? state.videoWidth.toDouble() : 1920,
            height: state.videoHeight > 0 ? state.videoHeight.toDouble() : 1080,
            child: texture,
          ),
        ),
      PlayerFit.cover => FittedBox(
          fit: BoxFit.cover,
          clipBehavior: Clip.hardEdge,
          child: SizedBox(
            width: state.videoWidth > 0 ? state.videoWidth.toDouble() : 1920,
            height: state.videoHeight > 0 ? state.videoHeight.toDouble() : 1080,
            child: texture,
          ),
        ),
      PlayerFit.fill => texture,
    };
  }

  Widget _buildPlaceholder() {
    final isLive = widget.source is LiveStreamMediaSource;

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            isLive ? Icons.live_tv_rounded : Icons.play_circle_fill,
            size: 64,
            color: Colors.white.withValues(alpha: 0.3),
          ),
          const SizedBox(height: 12),
          Text(
            _sourceLabel,
            style: const TextStyle(color: Colors.white38, fontSize: 13),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  String get _sourceLabel => switch (widget.source) {
        NetworkMediaSource(url: final url) => _truncateUrl(url),
        AssetMediaSource(assetPath: final p) => p.split('/').last,
        FileMediaSource(filePath: final p) => p.split('/').last,
        LiveStreamMediaSource(url: final url) => 'LIVE: ${_truncateUrl(url)}',
        MemoryMediaSource() => 'In-memory media',
      };

  String _truncateUrl(String url) {
    final uri = Uri.tryParse(url);
    if (uri == null) return url;
    final path = uri.pathSegments.isNotEmpty ? uri.pathSegments.last : url;
    return path.length > 40 ? '${path.substring(0, 37)}...' : path;
  }
}
