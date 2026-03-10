import 'dart:async';

import 'package:flutter/material.dart';

import '../api/models/player_config.dart';
import 'player_state.dart';
import 'secure_player_controller.dart';

/// Interactive player controls overlay for [SecureMediaPlayer].
///
/// Features:
/// - Play/pause center button
/// - Seek bar with buffered progress
/// - Double-tap left/right to seek ±10s
/// - Time display (position / duration)
/// - Volume control
/// - Playback speed selector
/// - Fullscreen toggle
/// - Auto-hide after [config.controlsAutoHideDelay]
/// - Live indicator for streams
class PlayerControls extends StatefulWidget {
  const PlayerControls({
    super.key,
    required this.controller,
    required this.config,
  });

  final SecurePlayerController controller;
  final PlayerConfig config;

  @override
  State<PlayerControls> createState() => _PlayerControlsState();
}

class _PlayerControlsState extends State<PlayerControls>
    with SingleTickerProviderStateMixin {
  bool _visible = true;
  Timer? _hideTimer;
  late final AnimationController _fadeController;
  late final Animation<double> _fadeAnimation;

  SecurePlayerController get _ctrl => widget.controller;
  PlayerState get _state => _ctrl.state;
  bool get _isLive => _state.isLive;

  @override
  void initState() {
    super.initState();
    _fadeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 250),
      value: 1.0,
    );
    _fadeAnimation = CurvedAnimation(
      parent: _fadeController,
      curve: Curves.easeInOut,
    );
    _scheduleHide();
  }

  @override
  void dispose() {
    _hideTimer?.cancel();
    _fadeController.dispose();
    super.dispose();
  }

  void _scheduleHide() {
    _hideTimer?.cancel();
    if (!_state.isPlaying) return;
    _hideTimer = Timer(widget.config.controlsAutoHideDelay, () {
      if (mounted && _state.isPlaying) {
        _fadeController.reverse();
        setState(() => _visible = false);
      }
    });
  }

  void _showControls() {
    _fadeController.forward();
    setState(() => _visible = true);
    _scheduleHide();
  }

  void _toggleVisibility() {
    if (_visible) {
      _hideTimer?.cancel();
      _fadeController.reverse();
      setState(() => _visible = false);
    } else {
      _showControls();
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: _ctrl,
      builder: (context, _) {
        return GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: _toggleVisibility,
          child: FadeTransition(
            opacity: _fadeAnimation,
            child: IgnorePointer(
              ignoring: !_visible,
              child: Stack(
                children: [
                  // Gradient scrim
                  _buildScrim(),

                  // Center play/pause button
                  Center(child: _buildCenterButton()),

                  // Bottom controls bar
                  Positioned(
                    left: 0,
                    right: 0,
                    bottom: 0,
                    child: _buildBottomBar(),
                  ),

                  // Top bar (live indicator, title)
                  if (_isLive)
                    Positioned(
                      top: 0,
                      left: 0,
                      right: 0,
                      child: _buildLiveIndicator(),
                    ),

                  // Double-tap seek zones
                  _buildSeekZones(),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildScrim() {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.center,
          colors: [Colors.black38, Colors.transparent],
        ),
      ),
      child: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.bottomCenter,
            end: Alignment.center,
            colors: [Colors.black54, Colors.transparent],
          ),
        ),
      ),
    );
  }

  Widget _buildCenterButton() {
    if (_state.isBuffering) {
      return const SizedBox(
        width: 48,
        height: 48,
        child: CircularProgressIndicator(
          color: Colors.white,
          strokeWidth: 3,
        ),
      );
    }

    final icon = switch (_state.status) {
      PlayerStatus.completed => Icons.replay,
      PlayerStatus.playing => Icons.pause_rounded,
      _ => Icons.play_arrow_rounded,
    };

    return GestureDetector(
      onTap: () {
        if (_state.status == PlayerStatus.completed) {
          _ctrl.seekTo(Duration.zero);
          _ctrl.play();
        } else {
          _ctrl.togglePlayPause();
        }
        _showControls();
      },
      child: Container(
        width: 56,
        height: 56,
        decoration: BoxDecoration(
          color: Colors.black.withValues(alpha: 0.5),
          shape: BoxShape.circle,
        ),
        child: Icon(icon, color: Colors.white, size: 36),
      ),
    );
  }

  Widget _buildBottomBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Seek bar
          if (!_isLive) _buildSeekBar(),

          // Controls row
          Row(
            children: [
              // Play/pause small icon
              _buildSmallButton(
                icon: _state.isPlaying
                    ? Icons.pause_rounded
                    : Icons.play_arrow_rounded,
                onTap: () {
                  _ctrl.togglePlayPause();
                  _showControls();
                },
              ),

              const SizedBox(width: 8),

              // Time display
              Text(
                _isLive
                    ? 'LIVE'
                    : '${_formatDuration(_state.position)}'
                        ' / ${_formatDuration(_state.duration)}',
                style: const TextStyle(
                  color: Colors.white70,
                  fontSize: 12,
                  fontFeatures: [FontFeature.tabularFigures()],
                ),
              ),

              const Spacer(),

              // Playback speed
              if (widget.config.allowPlaybackSpeed && !_isLive)
                _buildSpeedButton(),

              // Volume
              _buildVolumeButton(),

              // Fullscreen
              if (widget.config.allowFullscreen)
                _buildSmallButton(
                  icon: _state.isFullscreen
                      ? Icons.fullscreen_exit
                      : Icons.fullscreen,
                  onTap: () {
                    _ctrl.toggleFullscreen();
                    _showControls();
                  },
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSeekBar() {
    return SizedBox(
      height: 24,
      child: SliderTheme(
        data: SliderThemeData(
          trackHeight: 3,
          thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
          overlayShape: const RoundSliderOverlayShape(overlayRadius: 14),
          activeTrackColor: Colors.white,
          inactiveTrackColor: Colors.white24,
          thumbColor: Colors.white,
          overlayColor: Colors.white24,
          // Show buffered progress as secondary track
          secondaryActiveTrackColor: Colors.white.withValues(alpha: 0.4),
        ),
        child: Slider(
          value: _state.position.inMilliseconds.toDouble().clamp(
                0,
                _state.duration.inMilliseconds.toDouble().clamp(1, double.maxFinite),
              ),
          max: _state.duration.inMilliseconds.toDouble().clamp(1, double.maxFinite),
          secondaryTrackValue: _state.bufferedPosition.inMilliseconds
              .toDouble()
              .clamp(0, _state.duration.inMilliseconds.toDouble().clamp(1, double.maxFinite)),
          onChanged: (value) {
            _ctrl.seekTo(Duration(milliseconds: value.toInt()));
            _showControls();
          },
        ),
      ),
    );
  }

  Widget _buildSeekZones() {
    return Row(
      children: [
        // Left: seek backward
        Expanded(
          child: GestureDetector(
            behavior: HitTestBehavior.translucent,
            onDoubleTap: _isLive
                ? null
                : () {
                    _ctrl.seekBackward();
                    _showControls();
                  },
            child: const SizedBox.expand(),
          ),
        ),
        // Center: no seek zone (play/pause handled by center button)
        const Expanded(child: SizedBox.expand()),
        // Right: seek forward
        Expanded(
          child: GestureDetector(
            behavior: HitTestBehavior.translucent,
            onDoubleTap: _isLive
                ? null
                : () {
                    _ctrl.seekForward();
                    _showControls();
                  },
            child: const SizedBox.expand(),
          ),
        ),
      ],
    );
  }

  Widget _buildLiveIndicator() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: Colors.red,
              borderRadius: BorderRadius.circular(4),
            ),
            child: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.fiber_manual_record, color: Colors.white, size: 10),
                SizedBox(width: 4),
                Text(
                  'LIVE',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 1.2,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSmallButton({
    required IconData icon,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.all(4),
        child: Icon(icon, color: Colors.white70, size: 22),
      ),
    );
  }

  Widget _buildVolumeButton() {
    final icon = _state.volume == 0
        ? Icons.volume_off
        : _state.volume < 0.5
            ? Icons.volume_down
            : Icons.volume_up;

    return _buildSmallButton(
      icon: icon,
      onTap: () {
        // Toggle mute
        if (_state.volume > 0) {
          _ctrl.setVolume(0);
        } else {
          _ctrl.setVolume(1.0);
        }
        _showControls();
      },
    );
  }

  Widget _buildSpeedButton() {
    final speed = _state.playbackSpeed;
    final label = speed == 1.0 ? '1x' : '${speed}x';

    return GestureDetector(
      onTap: () => _showSpeedPicker(),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
        child: Text(
          label,
          style: const TextStyle(
            color: Colors.white70,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  void _showSpeedPicker() {
    const speeds = [0.5, 0.75, 1.0, 1.25, 1.5, 2.0];

    showModalBottomSheet<double>(
      context: context,
      backgroundColor: Colors.grey.shade900,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (ctx) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Padding(
                padding: EdgeInsets.all(16),
                child: Text(
                  'Playback Speed',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              ...speeds.map((s) {
                final isActive = _state.playbackSpeed == s;
                return ListTile(
                  title: Text(
                    '${s}x',
                    style: TextStyle(
                      color: isActive ? Colors.blue : Colors.white70,
                      fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
                    ),
                  ),
                  trailing: isActive
                      ? const Icon(Icons.check, color: Colors.blue, size: 20)
                      : null,
                  onTap: () {
                    _ctrl.setPlaybackSpeed(s);
                    Navigator.pop(ctx, s);
                    _showControls();
                  },
                );
              }),
              const SizedBox(height: 8),
            ],
          ),
        );
      },
    );
  }

  String _formatDuration(Duration d) {
    final hours = d.inHours;
    final minutes = d.inMinutes.remainder(60);
    final seconds = d.inSeconds.remainder(60);
    if (hours > 0) {
      return '$hours:${minutes.toString().padLeft(2, '0')}'
          ':${seconds.toString().padLeft(2, '0')}';
    }
    return '$minutes:${seconds.toString().padLeft(2, '0')}';
  }
}
