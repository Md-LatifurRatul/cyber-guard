import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../api/models/media_source.dart';
import '../api/models/player_config.dart';
import 'player_state.dart';

/// Controller for native media playback via MethodChannel.
///
/// Manages the lifecycle of a single native player instance:
/// create → initialize → play/pause/seek → dispose.
///
/// Each [SecurePlayerController] owns one native texture. The Dart
/// [Texture] widget uses [textureId] to render frames from the native
/// player (ExoPlayer on Android, AVPlayer on iOS/macOS, HTML5 on web).
///
/// ## Usage:
/// ```dart
/// final controller = SecurePlayerController(
///   source: MediaSource.network('https://example.com/video.mp4'),
///   config: const PlayerConfig(autoPlay: true),
/// );
/// await controller.initialize();
/// // ... Texture(textureId: controller.state.textureId!) ...
/// await controller.dispose();
/// ```
class SecurePlayerController extends ChangeNotifier {
  SecurePlayerController({
    required this.source,
    this.config = const PlayerConfig(),
  });

  /// The MethodChannel for player communication.
  static const _channel = MethodChannel('com.cyberguard.security/player');

  /// Media source to play.
  final MediaSource source;

  /// Player configuration.
  final PlayerConfig config;

  /// Current player state snapshot.
  PlayerState _state = const PlayerState();
  PlayerState get state => _state;

  /// Unique player ID assigned by the native side.
  String? _playerId;

  /// Position update timer for polling native position.
  Timer? _positionTimer;

  /// Whether [dispose] has been called.
  bool _disposed = false;

  // ─── Lifecycle ───

  /// Initialize the native player and obtain a texture ID.
  ///
  /// After this completes, [state.textureId] will be non-null and
  /// the [Texture] widget can render frames.
  Future<void> initialize() async {
    if (_disposed) return;

    try {
      final sourceData = _encodeSource(source);
      final result = await _channel.invokeMapMethod<String, dynamic>('create', {
        'source': sourceData,
        'config': _encodeConfig(config),
      });

      if (result == null) {
        _updateState(
          _state.copyWith(
            status: PlayerStatus.error,
            errorMessage: 'Native player returned null',
          ),
        );
        return;
      }

      _playerId = result['playerId'] as String?;
      final textureId = result['textureId'] as int?;

      _updateState(
        _state.copyWith(
          status: PlayerStatus.ready,
          textureId: textureId,
          volume: config.initialVolume,
          playbackSpeed: config.initialPlaybackSpeed,
        ),
      );

      // Listen for native events
      _channel.setMethodCallHandler(_handleNativeCall);

      // Start position polling
      _startPositionPolling();

      if (config.autoPlay) {
        await play();
      }
    } on PlatformException catch (e) {
      _updateState(
        _state.copyWith(
          status: PlayerStatus.error,
          errorMessage: e.message ?? 'Platform error: ${e.code}',
        ),
      );
    }
  }

  // ─── Playback Controls ───

  /// Start or resume playback.
  Future<void> play() async {
    if (_disposed || _playerId == null) return;
    try {
      await _channel.invokeMethod('play', {'playerId': _playerId});
      _updateState(_state.copyWith(status: PlayerStatus.playing));
    } on PlatformException catch (e) {
      _updateState(
        _state.copyWith(status: PlayerStatus.error, errorMessage: e.message),
      );
    }
  }

  /// Pause playback.
  Future<void> pause() async {
    if (_disposed || _playerId == null) return;
    try {
      await _channel.invokeMethod('pause', {'playerId': _playerId});
      _updateState(_state.copyWith(status: PlayerStatus.paused));
    } on PlatformException catch (e) {
      _updateState(
        _state.copyWith(status: PlayerStatus.error, errorMessage: e.message),
      );
    }
  }

  /// Toggle between play and pause.
  Future<void> togglePlayPause() async {
    if (_state.isPlaying) {
      await pause();
    } else {
      await play();
    }
  }

  /// Seek to a specific position.
  Future<void> seekTo(Duration position) async {
    if (_disposed || _playerId == null) return;
    try {
      await _channel.invokeMethod('seekTo', {
        'playerId': _playerId,
        'positionMs': position.inMilliseconds,
      });
      _updateState(_state.copyWith(position: position));
    } on PlatformException catch (e) {
      debugPrint('CyberGuard: Seek error: ${e.message}');
    }
  }

  /// Seek forward by [config.seekDuration].
  Future<void> seekForward() async {
    final target = _state.position + config.seekDuration;
    final clamped = target > _state.duration ? _state.duration : target;
    await seekTo(clamped);
  }

  /// Seek backward by [config.seekDuration].
  Future<void> seekBackward() async {
    final target = _state.position - config.seekDuration;
    final clamped = target < Duration.zero ? Duration.zero : target;
    await seekTo(clamped);
  }

  /// Set playback volume (0.0 – 1.0).
  Future<void> setVolume(double volume) async {
    if (_disposed || _playerId == null) return;
    final clamped = volume.clamp(0.0, 1.0);
    try {
      await _channel.invokeMethod('setVolume', {
        'playerId': _playerId,
        'volume': clamped,
      });
      _updateState(_state.copyWith(volume: clamped));
    } on PlatformException catch (e) {
      debugPrint('CyberGuard: Volume error: ${e.message}');
    }
  }

  /// Set playback speed multiplier (0.25 – 4.0).
  Future<void> setPlaybackSpeed(double speed) async {
    if (_disposed || _playerId == null) return;
    final clamped = speed.clamp(0.25, 4.0);
    try {
      await _channel.invokeMethod('setPlaybackSpeed', {
        'playerId': _playerId,
        'speed': clamped,
      });
      _updateState(_state.copyWith(playbackSpeed: clamped));
    } on PlatformException catch (e) {
      debugPrint('CyberGuard: Speed error: ${e.message}');
    }
  }

  /// Toggle fullscreen mode.
  void toggleFullscreen() {
    _updateState(_state.copyWith(isFullscreen: !_state.isFullscreen));
  }

  // ─── Native Event Handling ───

  Future<dynamic> _handleNativeCall(MethodCall call) async {
    if (_disposed) return;

    switch (call.method) {
      case 'onReady':
        final args = call.arguments as Map<dynamic, dynamic>? ?? {};
        _updateState(
          _state.copyWith(
            status: PlayerStatus.ready,
            duration: Duration(milliseconds: (args['durationMs'] as int?) ?? 0),
            videoWidth: (args['videoWidth'] as int?) ?? 0,
            videoHeight: (args['videoHeight'] as int?) ?? 0,
          ),
        );

      case 'onBuffering':
        _updateState(_state.copyWith(status: PlayerStatus.buffering));

      case 'onPlaying':
        _updateState(_state.copyWith(status: PlayerStatus.playing));

      case 'onPaused':
        _updateState(_state.copyWith(status: PlayerStatus.paused));

      case 'onCompleted':
        _updateState(_state.copyWith(status: PlayerStatus.completed));
        if (config.looping) {
          await seekTo(Duration.zero);
          await play();
        }

      case 'onPositionUpdate':
        final args = call.arguments as Map<dynamic, dynamic>? ?? {};
        _updateState(
          _state.copyWith(
            position: Duration(milliseconds: (args['positionMs'] as int?) ?? 0),
            bufferedPosition: Duration(
              milliseconds: (args['bufferedMs'] as int?) ?? 0,
            ),
          ),
        );

      case 'onVideoSizeChanged':
        final args = call.arguments as Map<dynamic, dynamic>? ?? {};
        _updateState(
          _state.copyWith(
            videoWidth: (args['width'] as int?) ?? 0,
            videoHeight: (args['height'] as int?) ?? 0,
          ),
        );

      case 'onError':
        final args = call.arguments as Map<dynamic, dynamic>? ?? {};
        _updateState(
          _state.copyWith(
            status: PlayerStatus.error,
            errorMessage: (args['message'] as String?) ?? 'Unknown error',
          ),
        );
    }
  }

  // ─── Position Polling ───

  void _startPositionPolling() {
    _positionTimer?.cancel();
    _positionTimer = Timer.periodic(
      const Duration(milliseconds: 250),
      (_) => _pollPosition(),
    );
  }

  Future<void> _pollPosition() async {
    if (_disposed || _playerId == null || !_state.isPlaying) return;
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'getPosition',
        {'playerId': _playerId},
      );
      if (result != null && !_disposed) {
        _updateState(
          _state.copyWith(
            position: Duration(
              milliseconds: (result['positionMs'] as int?) ?? 0,
            ),
            bufferedPosition: Duration(
              milliseconds: (result['bufferedMs'] as int?) ?? 0,
            ),
          ),
        );
      }
    } on PlatformException {
      // Ignore polling errors silently
    }
  }

  // ─── Source Encoding ───

  Map<String, dynamic> _encodeSource(MediaSource source) {
    return switch (source) {
      NetworkMediaSource(url: final url, headers: final headers) => {
        'type': 'network',
        'url': url,
        'headers': headers,
      },
      AssetMediaSource(assetPath: final path) => {
        'type': 'asset',
        'assetPath': path,
      },
      FileMediaSource(filePath: final path) => {
        'type': 'file',
        'filePath': path,
      },
      LiveStreamMediaSource(url: final url, headers: final headers) => {
        'type': 'liveStream',
        'url': url,
        'headers': headers,
      },
      MemoryMediaSource(bytes: final bytes, mimeType: final mime) => {
        'type': 'memory',
        'bytes': bytes,
        'mimeType': mime,
      },
    };
  }

  Map<String, dynamic> _encodeConfig(PlayerConfig config) {
    return {
      'autoPlay': config.autoPlay,
      'looping': config.looping,
      'volume': config.initialVolume,
      'speed': config.initialPlaybackSpeed,
      'fit': config.fit.name,
    };
  }

  // ─── State Management ───

  void _updateState(PlayerState newState) {
    if (_disposed) return;
    _state = newState;
    notifyListeners();
  }

  // ─── Disposal ───

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    _positionTimer?.cancel();
    _positionTimer = null;

    if (_playerId != null) {
      try {
        await _channel.invokeMethod('dispose', {'playerId': _playerId});
      } on PlatformException {
        // Best-effort cleanup
      }
    }

    super.dispose();
  }
}
