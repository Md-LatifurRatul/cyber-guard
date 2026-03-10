import AVFoundation
import Flutter
import UIKit

/// Secure Media Player Plugin for iOS.
///
/// Uses AVPlayer to decode media and renders frames to a Flutter Texture
/// via CVPixelBuffer. The Dart side displays these frames using
/// Flutter's `Texture(textureId)` widget.
///
/// ## How it works:
///
/// 1. Dart calls "create" with source + config
/// 2. We create an AVPlayerItemVideoOutput to get CVPixelBuffers
/// 3. A CADisplayLink drives frame delivery to Flutter's texture
/// 4. Flutter composites the texture into its widget tree (GPU-direct)
/// 5. Dart controls playback via play/pause/seek/volume/speed calls
///
/// ## Channel: "com.cyberguard.security/player"
class SecurePlayerPlugin: NSObject, FlutterPlugin {

    static let channelName = "com.cyberguard.security/player"

    private var methodChannel: FlutterMethodChannel?
    private var textureRegistry: FlutterTextureRegistry?

    /// Active player instances (playerId → PlayerInstance)
    private var players: [String: PlayerInstance] = [:]

    override init() {
        self.methodChannel = nil
        self.textureRegistry = nil
        super.init()
    }

    // MARK: - FlutterPlugin

    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: channelName,
            binaryMessenger: registrar.messenger()
        )
        let instance = SecurePlayerPlugin()
        instance.methodChannel = channel
        instance.textureRegistry = registrar.textures()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "create":
            handleCreate(call, result: result)
        case "play":
            handlePlay(call, result: result)
        case "pause":
            handlePause(call, result: result)
        case "seekTo":
            handleSeekTo(call, result: result)
        case "setVolume":
            handleSetVolume(call, result: result)
        case "setPlaybackSpeed":
            handleSetSpeed(call, result: result)
        case "getPosition":
            handleGetPosition(call, result: result)
        case "dispose":
            handleDispose(call, result: result)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // MARK: - Create Player

    private func handleCreate(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let registry = textureRegistry else {
            result(
                FlutterError(
                    code: "NO_REGISTRY", message: "Texture registry unavailable", details: nil))
            return
        }

        guard let args = call.arguments as? [String: Any],
            let sourceMap = args["source"] as? [String: Any]
        else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing source", details: nil))
            return
        }

        let configMap = args["config"] as? [String: Any]
        let playerId = UUID().uuidString

        // Build AVPlayerItem from source
        guard let playerItem = buildPlayerItem(from: sourceMap) else {
            result(
                FlutterError(
                    code: "INVALID_SOURCE", message: "Could not create media item", details: nil))
            return
        }

        // Create AVPlayer
        let avPlayer = AVPlayer(playerItem: playerItem)

        // Apply config
        if let config = configMap {
            avPlayer.volume = Float(config["volume"] as? Double ?? 1.0)
            avPlayer.rate = Float(config["speed"] as? Double ?? 1.0)
        }

        // Create pixel buffer output for Flutter texture
        let videoOutput = AVPlayerItemVideoOutput(pixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA
        ])
        playerItem.add(videoOutput)

        // Create Flutter texture
        let textureRenderer = PlayerTextureRenderer(videoOutput: videoOutput)
        let textureId = registry.register(textureRenderer)

        // Create display link for frame delivery
        let displayLink = CADisplayLink(
            target: textureRenderer, selector: #selector(PlayerTextureRenderer.onDisplayLink(_:)))
        displayLink.add(to: .main, forMode: .common)

        // Store instance
        let instance = PlayerInstance(
            playerId: playerId,
            avPlayer: avPlayer,
            playerItem: playerItem,
            videoOutput: videoOutput,
            textureRenderer: textureRenderer,
            textureId: textureId,
            displayLink: displayLink,
            textureRegistry: registry
        )
        players[playerId] = instance

        // Observe player events
        instance.observeEvents { [weak self] event, data in
            self?.sendToFlutter(event, data: data, playerId: playerId)
        }

        // Auto-play if configured
        if configMap?["autoPlay"] as? Bool == true {
            avPlayer.play()
        }

        result(
            [
                "playerId": playerId,
                "textureId": Int(textureId),
            ] as [String: Any])
    }

    // MARK: - Playback Controls

    private func handlePlay(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        player.avPlayer.play()
        result(nil)
    }

    private func handlePause(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        player.avPlayer.pause()
        result(nil)
    }

    private func handleSeekTo(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        let args = call.arguments as? [String: Any]
        let positionMs = args?["positionMs"] as? Int ?? 0
        let time = CMTime(value: CMTimeValue(positionMs), timescale: 1000)
        player.avPlayer.seek(to: time, toleranceBefore: .zero, toleranceAfter: .zero)
        result(nil)
    }

    private func handleSetVolume(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        let args = call.arguments as? [String: Any]
        let volume = Float(args?["volume"] as? Double ?? 1.0)
        player.avPlayer.volume = min(max(volume, 0), 1)
        result(nil)
    }

    private func handleSetSpeed(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        let args = call.arguments as? [String: Any]
        let speed = Float(args?["speed"] as? Double ?? 1.0)
        player.avPlayer.rate = min(max(speed, 0.25), 4.0)
        result(nil)
    }

    private func handleGetPosition(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let player = getPlayer(call, result: result) else { return }
        let positionMs = Int(CMTimeGetSeconds(player.avPlayer.currentTime()) * 1000)

        var bufferedMs = 0
        if let range = player.playerItem.loadedTimeRanges.last?.timeRangeValue {
            bufferedMs = Int(
                (CMTimeGetSeconds(range.start) + CMTimeGetSeconds(range.duration)) * 1000)
        }

        result(
            [
                "positionMs": max(positionMs, 0),
                "bufferedMs": max(bufferedMs, 0),
            ] as [String: Any])
    }

    private func handleDispose(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]
        guard let playerId = args?["playerId"] as? String else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing playerId", details: nil))
            return
        }

        players[playerId]?.release()
        players.removeValue(forKey: playerId)
        result(nil)
    }

    // MARK: - Helpers

    private func getPlayer(_ call: FlutterMethodCall, result: @escaping FlutterResult)
        -> PlayerInstance?
    {
        let args = call.arguments as? [String: Any]
        guard let playerId = args?["playerId"] as? String,
            let player = players[playerId]
        else {
            result(FlutterError(code: "PLAYER_NOT_FOUND", message: "No player found", details: nil))
            return nil
        }
        return player
    }

    private func buildPlayerItem(from source: [String: Any]) -> AVPlayerItem? {
        let type = source["type"] as? String ?? "network"
        var url: URL?

        switch type {
        case "network", "liveStream":
            if let urlStr = source["url"] as? String {
                url = URL(string: urlStr)
            }
        case "asset":
            if let assetPath = source["assetPath"] as? String {
                let key = FlutterDartProject.lookupKey(forAsset: assetPath)
                if let path = Bundle.main.path(forResource: key, ofType: nil) {
                    url = URL(fileURLWithPath: path)
                }
            }
        case "file":
            if let filePath = source["filePath"] as? String {
                url = URL(fileURLWithPath: filePath)
            }
        default:
            if let urlStr = source["url"] as? String {
                url = URL(string: urlStr)
            }
        }

        guard let mediaUrl = url else { return nil }
        return AVPlayerItem(url: mediaUrl)
    }

    private func sendToFlutter(_ event: String, data: [String: Any], playerId: String) {
        DispatchQueue.main.async { [weak self] in
            var args = data
            args["playerId"] = playerId
            self?.methodChannel?.invokeMethod(event, arguments: args)
        }
    }
}

// MARK: - Player Texture Renderer

/// Delivers CVPixelBuffer frames from AVPlayerItemVideoOutput to Flutter's texture system.
class PlayerTextureRenderer: NSObject, FlutterTexture {
    private let videoOutput: AVPlayerItemVideoOutput
    private var lastPixelBuffer: CVPixelBuffer?

    init(videoOutput: AVPlayerItemVideoOutput) {
        self.videoOutput = videoOutput
        super.init()
    }

    func copyPixelBuffer() -> Unmanaged<CVPixelBuffer>? {
        guard let buffer = lastPixelBuffer else { return nil }
        return Unmanaged.passRetained(buffer)
    }

    @objc func onDisplayLink(_ displayLink: CADisplayLink) {
        let time = videoOutput.itemTime(forHostTime: CACurrentMediaTime())
        if videoOutput.hasNewPixelBuffer(forItemTime: time) {
            lastPixelBuffer = videoOutput.copyPixelBuffer(
                forItemTime: time, itemTimeForDisplay: nil)
        }
    }
}

// MARK: - Player Instance

private class PlayerInstance {
    let playerId: String
    let avPlayer: AVPlayer
    let playerItem: AVPlayerItem
    let videoOutput: AVPlayerItemVideoOutput
    let textureRenderer: PlayerTextureRenderer
    let textureId: Int64
    let displayLink: CADisplayLink
    let textureRegistry: FlutterTextureRegistry

    private var statusObservation: NSKeyValueObservation?
    private var timeObserver: Any?
    private var didEndObserver: NSObjectProtocol?

    init(
        playerId: String,
        avPlayer: AVPlayer,
        playerItem: AVPlayerItem,
        videoOutput: AVPlayerItemVideoOutput,
        textureRenderer: PlayerTextureRenderer,
        textureId: Int64,
        displayLink: CADisplayLink,
        textureRegistry: FlutterTextureRegistry
    ) {
        self.playerId = playerId
        self.avPlayer = avPlayer
        self.playerItem = playerItem
        self.videoOutput = videoOutput
        self.textureRenderer = textureRenderer
        self.textureId = textureId
        self.displayLink = displayLink
        self.textureRegistry = textureRegistry
    }

    func observeEvents(callback: @escaping (String, [String: Any]) -> Void) {
        // Observe playback status
        statusObservation = playerItem.observe(\.status, options: [.new]) { [weak self] item, _ in
            guard let self = self else { return }
            switch item.status {
            case .readyToPlay:
                let duration = CMTimeGetSeconds(item.duration)
                let tracks = item.tracks.compactMap { $0.assetTrack }
                let videoTrack = tracks.first { $0.mediaType == .video }
                let size = videoTrack?.naturalSize ?? .zero
                callback(
                    "onReady",
                    [
                        "durationMs": Int(duration * 1000),
                        "videoWidth": Int(size.width),
                        "videoHeight": Int(size.height),
                    ])
            case .failed:
                callback(
                    "onError",
                    [
                        "message": item.error?.localizedDescription ?? "Playback failed"
                    ])
            default:
                break
            }
        }

        // Observe playback completion
        didEndObserver = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime,
            object: playerItem,
            queue: .main
        ) { _ in
            callback("onCompleted", [:])
        }

        // Periodic time updates for texture refresh
        let interval = CMTime(seconds: 1.0 / 60.0, preferredTimescale: CMTimeScale(NSEC_PER_SEC))
        timeObserver = avPlayer.addPeriodicTimeObserver(forInterval: interval, queue: .main) {
            [weak self] _ in
            guard let self = self else { return }
            self.textureRegistry.textureFrameAvailable(self.textureId)
        }
    }

    func release() {
        displayLink.invalidate()
        statusObservation?.invalidate()
        statusObservation = nil

        if let observer = didEndObserver {
            NotificationCenter.default.removeObserver(observer)
            didEndObserver = nil
        }

        if let observer = timeObserver {
            avPlayer.removeTimeObserver(observer)
            timeObserver = nil
        }

        avPlayer.pause()
        playerItem.remove(videoOutput)
        textureRegistry.unregisterTexture(textureId)
    }
}
