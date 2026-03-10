import 'package:flutter/material.dart';

import 'player_state.dart';
import 'secure_player_controller.dart';

/// Overlay states for the secure media player.
///
/// Displays contextual overlays based on [PlayerState.status]:
/// - **Buffering:** centered spinner with "Buffering..." label
/// - **Error:** error icon + message + retry button
/// - **Completed:** replay icon + "Play again" button
/// - **Idle:** loading shimmer placeholder
///
/// This widget is transparent when the player is actively playing,
/// allowing the native [Texture] to show through.
class PlayerOverlay extends StatelessWidget {
  const PlayerOverlay({super.key, required this.controller, this.onRetry});

  final SecurePlayerController controller;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final state = controller.state;

        return switch (state.status) {
          PlayerStatus.idle => _buildLoading(),
          PlayerStatus.buffering => _buildBuffering(),
          PlayerStatus.error => _buildError(
            state.errorMessage ?? 'Unknown error',
          ),
          PlayerStatus.completed => _buildCompleted(),
          _ => const SizedBox.shrink(),
        };
      },
    );
  }

  Widget _buildLoading() {
    return Container(
      color: Colors.black,
      child: const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(color: Colors.white54, strokeWidth: 2.5),
            SizedBox(height: 16),
            Text(
              'Initializing player...',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBuffering() {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            width: 36,
            height: 36,
            child: CircularProgressIndicator(
              color: Colors.white,
              strokeWidth: 2.5,
            ),
          ),
          SizedBox(height: 12),
          Text(
            'Buffering...',
            style: TextStyle(color: Colors.white70, fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _buildError(String message) {
    return Container(
      color: Colors.black87,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(
                Icons.error_outline_rounded,
                size: 48,
                color: Colors.redAccent,
              ),
              const SizedBox(height: 12),
              Text(
                message,
                style: const TextStyle(color: Colors.white70, fontSize: 13),
                textAlign: TextAlign.center,
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 16),
              TextButton.icon(
                onPressed: onRetry ?? () => controller.initialize(),
                icon: const Icon(Icons.refresh, size: 18),
                label: const Text('Retry'),
                style: TextButton.styleFrom(
                  foregroundColor: Colors.white,
                  backgroundColor: Colors.white12,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 10,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildCompleted() {
    return Container(
      color: Colors.black54,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            GestureDetector(
              onTap: () {
                controller.seekTo(Duration.zero);
                controller.play();
              },
              child: Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.5),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.replay_rounded,
                  color: Colors.white,
                  size: 32,
                ),
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              'Play again',
              style: TextStyle(color: Colors.white70, fontSize: 13),
            ),
          ],
        ),
      ),
    );
  }
}
