package com.myapp.cyber_guard

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Surface
import androidx.media3.common.C
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.VideoSize
import androidx.media3.exoplayer.ExoPlayer
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.view.TextureRegistry
import java.util.UUID

/**
 * Secure Media Player Plugin for Android.
 *
 * Uses AndroidX Media3 ExoPlayer to decode media and renders frames
 * to a Flutter Texture via SurfaceTexture. The Dart side displays
 * these frames using Flutter's `Texture(textureId)` widget.
 *
 * ## How it works:
 *
 * 1. Dart calls "create" with source + config
 * 2. We register a SurfaceTexture with Flutter's TextureRegistry
 * 3. ExoPlayer renders decoded frames to this SurfaceTexture
 * 4. Flutter composites the texture into its widget tree (GPU-direct)
 * 5. Dart controls playback via play/pause/seek/volume/speed calls
 * 6. Player events (ready, buffering, error) are sent back to Dart
 *
 * ## Security:
 * - Rendered via GPU texture — no CPU pixel readback possible
 * - Combined with FLAG_SECURE from CyberGuardPlugin
 * - No DRM content keys exposed to Dart layer
 *
 * ## Channel: "com.cyberguard.security/player"
 */
class SecurePlayerPlugin : FlutterPlugin, MethodCallHandler {

    companion object {
        private const val TAG = "SecurePlayerPlugin"
        private const val CHANNEL = "com.cyberguard.security/player"
    }

    private var methodChannel: MethodChannel? = null
    private var textureRegistry: TextureRegistry? = null
    private var applicationContext: Context? = null

    // Active player instances (playerId → PlayerInstance)
    private val players = mutableMapOf<String, PlayerInstance>()

    private val mainHandler = Handler(Looper.getMainLooper())

    // ─── FlutterPlugin lifecycle ───

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel = MethodChannel(binding.binaryMessenger, CHANNEL).apply {
            setMethodCallHandler(this@SecurePlayerPlugin)
        }
        textureRegistry = binding.textureRegistry
        applicationContext = binding.applicationContext

        Log.i(TAG, "SecurePlayerPlugin attached")
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel?.setMethodCallHandler(null)
        methodChannel = null

        // Dispose all active players
        players.values.forEach { it.release() }
        players.clear()

        textureRegistry = null
        applicationContext = null

        Log.i(TAG, "SecurePlayerPlugin detached")
    }

    // ─── Method call handler ───

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "create" -> handleCreate(call, result)
            "play" -> handlePlay(call, result)
            "pause" -> handlePause(call, result)
            "seekTo" -> handleSeekTo(call, result)
            "setVolume" -> handleSetVolume(call, result)
            "setPlaybackSpeed" -> handleSetSpeed(call, result)
            "getPosition" -> handleGetPosition(call, result)
            "dispose" -> handleDispose(call, result)
            else -> result.notImplemented()
        }
    }

    // ─── Create player ───

    private fun handleCreate(call: MethodCall, result: Result) {
        val context = applicationContext
        val registry = textureRegistry
        if (context == null || registry == null) {
            result.error("NO_CONTEXT", "Plugin not attached to engine", null)
            return
        }

        try {
            val sourceMap = call.argument<Map<String, Any>>("source")
            val configMap = call.argument<Map<String, Any>>("config")

            if (sourceMap == null) {
                result.error("INVALID_ARGS", "Missing 'source' argument", null)
                return
            }

            val playerId = UUID.randomUUID().toString()

            // Register a texture with Flutter
            val textureEntry = registry.createSurfaceTexture()
            val textureId = textureEntry.id()
            val surface = Surface(textureEntry.surfaceTexture())

            // Create ExoPlayer instance
            val exoPlayer = ExoPlayer.Builder(context).build()

            // Set surface for rendering
            exoPlayer.setVideoSurface(surface)

            // Apply config
            configMap?.let { config ->
                exoPlayer.volume = (config["volume"] as? Double)?.toFloat() ?: 1.0f
                exoPlayer.playbackParameters = exoPlayer.playbackParameters.withSpeed(
                    (config["speed"] as? Double)?.toFloat() ?: 1.0f
                )
                exoPlayer.repeatMode = if (config["looping"] == true) {
                    Player.REPEAT_MODE_ALL
                } else {
                    Player.REPEAT_MODE_OFF
                }
            }

            // Build MediaItem from source
            val mediaItem = buildMediaItem(sourceMap)

            // Store player instance
            val instance = PlayerInstance(
                playerId = playerId,
                exoPlayer = exoPlayer,
                textureEntry = textureEntry,
                surface = surface,
            )
            players[playerId] = instance

            // Attach event listener
            exoPlayer.addListener(PlayerEventListener(playerId))

            // Set media and prepare
            exoPlayer.setMediaItem(mediaItem)
            exoPlayer.prepare()

            // Auto-play if configured
            if (configMap?.get("autoPlay") == true) {
                exoPlayer.playWhenReady = true
            }

            Log.i(TAG, "Player created: $playerId (texture: $textureId)")

            result.success(mapOf(
                "playerId" to playerId,
                "textureId" to textureId.toInt(),
            ))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create player: ${e.message}")
            result.error("CREATE_FAILED", e.message, null)
        }
    }

    // ─── Playback controls ───

    private fun handlePlay(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        player.exoPlayer.playWhenReady = true
        result.success(null)
    }

    private fun handlePause(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        player.exoPlayer.playWhenReady = false
        result.success(null)
    }

    private fun handleSeekTo(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        val positionMs = call.argument<Int>("positionMs")?.toLong() ?: 0L
        player.exoPlayer.seekTo(positionMs)
        result.success(null)
    }

    private fun handleSetVolume(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        val volume = (call.argument<Double>("volume") ?: 1.0).toFloat()
        player.exoPlayer.volume = volume.coerceIn(0f, 1f)
        result.success(null)
    }

    private fun handleSetSpeed(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        val speed = (call.argument<Double>("speed") ?: 1.0).toFloat()
        player.exoPlayer.playbackParameters = player.exoPlayer.playbackParameters.withSpeed(
            speed.coerceIn(0.25f, 4f)
        )
        result.success(null)
    }

    private fun handleGetPosition(call: MethodCall, result: Result) {
        val player = getPlayer(call, result) ?: return
        val exo = player.exoPlayer
        result.success(mapOf(
            "positionMs" to exo.currentPosition.toInt(),
            "bufferedMs" to exo.bufferedPosition.toInt(),
        ))
    }

    private fun handleDispose(call: MethodCall, result: Result) {
        val playerId = call.argument<String>("playerId")
        if (playerId == null) {
            result.error("INVALID_ARGS", "Missing playerId", null)
            return
        }

        players.remove(playerId)?.release()
        Log.i(TAG, "Player disposed: $playerId")
        result.success(null)
    }

    // ─── Helpers ───

    private fun getPlayer(call: MethodCall, result: Result): PlayerInstance? {
        val playerId = call.argument<String>("playerId")
        val player = players[playerId]
        if (player == null) {
            result.error("PLAYER_NOT_FOUND", "No player with id: $playerId", null)
        }
        return player
    }

    private fun buildMediaItem(sourceMap: Map<String, Any>): MediaItem {
        val type = sourceMap["type"] as? String ?: "network"
        val url = sourceMap["url"] as? String
        val assetPath = sourceMap["assetPath"] as? String
        val filePath = sourceMap["filePath"] as? String
        val headers = sourceMap["headers"] as? Map<*, *>

        val uri = when (type) {
            "network", "liveStream" -> Uri.parse(url ?: "")
            "asset" -> Uri.parse("asset:///flutter_assets/$assetPath")
            "file" -> Uri.parse("file://$filePath")
            else -> Uri.parse(url ?: "")
        }

        val builder = MediaItem.Builder().setUri(uri)

        // Hint MIME type for live streams
        if (type == "liveStream") {
            val urlLower = (url ?: "").lowercase()
            when {
                urlLower.contains(".m3u8") -> builder.setMimeType("application/x-mpegURL")
                urlLower.contains(".mpd") -> builder.setMimeType("application/dash+xml")
            }
        }

        return builder.build()
    }

    // ─── Player event listener ───

    private inner class PlayerEventListener(
        private val playerId: String
    ) : Player.Listener {

        override fun onPlaybackStateChanged(playbackState: Int) {
            when (playbackState) {
                Player.STATE_READY -> {
                    val player = players[playerId]?.exoPlayer ?: return
                    sendToFlutter("onReady", mapOf(
                        "durationMs" to player.duration.coerceAtLeast(0).toInt(),
                        "videoWidth" to (player.videoSize.width),
                        "videoHeight" to (player.videoSize.height),
                    ))
                }
                Player.STATE_BUFFERING -> {
                    sendToFlutter("onBuffering", emptyMap())
                }
                Player.STATE_ENDED -> {
                    sendToFlutter("onCompleted", emptyMap())
                }
                Player.STATE_IDLE -> { /* no-op */ }
            }
        }

        override fun onIsPlayingChanged(isPlaying: Boolean) {
            if (isPlaying) {
                sendToFlutter("onPlaying", emptyMap())
            } else {
                val player = players[playerId]?.exoPlayer ?: return
                if (player.playbackState == Player.STATE_READY) {
                    sendToFlutter("onPaused", emptyMap())
                }
            }
        }

        override fun onVideoSizeChanged(videoSize: VideoSize) {
            sendToFlutter("onVideoSizeChanged", mapOf(
                "width" to videoSize.width,
                "height" to videoSize.height,
            ))
        }

        override fun onPlayerError(error: PlaybackException) {
            Log.e(TAG, "Player error [$playerId]: ${error.message}")
            sendToFlutter("onError", mapOf(
                "message" to (error.message ?: "Playback error: ${error.errorCodeName}"),
            ))
        }

        private fun sendToFlutter(method: String, args: Map<String, Any>) {
            mainHandler.post {
                methodChannel?.invokeMethod(method, args + ("playerId" to playerId))
            }
        }
    }

    // ─── Player instance holder ───

    private data class PlayerInstance(
        val playerId: String,
        val exoPlayer: ExoPlayer,
        val textureEntry: TextureRegistry.SurfaceTextureEntry,
        val surface: Surface,
    ) {
        fun release() {
            exoPlayer.stop()
            exoPlayer.release()
            surface.release()
            textureEntry.release()
        }
    }
}
