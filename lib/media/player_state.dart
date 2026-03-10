/// Player state model for the secure media engine.
///
/// Immutable snapshot of the current player state. Updated by
/// [SecurePlayerController] and consumed by [PlayerControls] and
/// [SecureMediaPlayer] for UI rendering.
class PlayerState {
  const PlayerState({
    this.status = PlayerStatus.idle,
    this.position = Duration.zero,
    this.duration = Duration.zero,
    this.bufferedPosition = Duration.zero,
    this.volume = 1.0,
    this.playbackSpeed = 1.0,
    this.isFullscreen = false,
    this.textureId,
    this.videoWidth = 0,
    this.videoHeight = 0,
    this.errorMessage,
  });

  /// Current playback status.
  final PlayerStatus status;

  /// Current playback position.
  final Duration position;

  /// Total media duration (zero for live streams).
  final Duration duration;

  /// How far ahead the player has buffered.
  final Duration bufferedPosition;

  /// Current volume (0.0 – 1.0).
  final double volume;

  /// Current playback speed multiplier.
  final double playbackSpeed;

  /// Whether the player is in fullscreen mode.
  final bool isFullscreen;

  /// Native texture ID for rendering via Flutter's [Texture] widget.
  /// `null` until the native player is initialized.
  final int? textureId;

  /// Native video width in pixels (0 until first frame).
  final int videoWidth;

  /// Native video height in pixels (0 until first frame).
  final int videoHeight;

  /// Error description when [status] is [PlayerStatus.error].
  final String? errorMessage;

  /// Whether the player is actively playing content.
  bool get isPlaying => status == PlayerStatus.playing;

  /// Whether the player is paused.
  bool get isPaused => status == PlayerStatus.paused;

  /// Whether the player is buffering (may also be playing at reduced rate).
  bool get isBuffering => status == PlayerStatus.buffering;

  /// Whether the player has encountered an error.
  bool get hasError => status == PlayerStatus.error;

  /// Whether the player has been initialized and is ready.
  bool get isReady =>
      status != PlayerStatus.idle && status != PlayerStatus.error;

  /// Whether this is a live stream (no finite duration).
  bool get isLive => duration == Duration.zero && isReady;

  /// Playback progress as a fraction (0.0 – 1.0).
  /// Returns 0 for live streams or when duration is zero.
  double get progress {
    if (duration.inMilliseconds <= 0) return 0.0;
    return (position.inMilliseconds / duration.inMilliseconds).clamp(0.0, 1.0);
  }

  /// Buffered progress as a fraction (0.0 – 1.0).
  double get bufferedProgress {
    if (duration.inMilliseconds <= 0) return 0.0;
    return (bufferedPosition.inMilliseconds / duration.inMilliseconds)
        .clamp(0.0, 1.0);
  }

  /// Aspect ratio derived from native video dimensions.
  /// Returns 16/9 as default when dimensions are unknown.
  double get aspectRatio {
    if (videoWidth > 0 && videoHeight > 0) {
      return videoWidth / videoHeight;
    }
    return 16 / 9;
  }

  /// Create a copy with updated fields.
  PlayerState copyWith({
    PlayerStatus? status,
    Duration? position,
    Duration? duration,
    Duration? bufferedPosition,
    double? volume,
    double? playbackSpeed,
    bool? isFullscreen,
    int? textureId,
    int? videoWidth,
    int? videoHeight,
    String? errorMessage,
  }) {
    return PlayerState(
      status: status ?? this.status,
      position: position ?? this.position,
      duration: duration ?? this.duration,
      bufferedPosition: bufferedPosition ?? this.bufferedPosition,
      volume: volume ?? this.volume,
      playbackSpeed: playbackSpeed ?? this.playbackSpeed,
      isFullscreen: isFullscreen ?? this.isFullscreen,
      textureId: textureId ?? this.textureId,
      videoWidth: videoWidth ?? this.videoWidth,
      videoHeight: videoHeight ?? this.videoHeight,
      errorMessage: errorMessage ?? this.errorMessage,
    );
  }

  @override
  String toString() =>
      'PlayerState($status, ${position.inSeconds}s/${duration.inSeconds}s, '
      'texture=$textureId, ${videoWidth}x$videoHeight)';
}

/// Playback status states.
enum PlayerStatus {
  /// Player not initialized yet.
  idle,

  /// Player initialized, waiting for play command.
  ready,

  /// Actively buffering data (may show spinner).
  buffering,

  /// Actively playing content.
  playing,

  /// Playback paused by user.
  paused,

  /// Playback reached end of media.
  completed,

  /// An error occurred (see [PlayerState.errorMessage]).
  error,
}
