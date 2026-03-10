import FlutterMacOS
import AVFoundation
import AppKit

/// Secure Media Player Plugin for macOS.
///
/// Uses AVPlayer to decode media and renders frames to a Flutter Texture
/// via CVPixelBuffer. Same architecture as iOS plugin with macOS-specific
/// API adaptations (FlutterMacOS framework, NSView, etc.).
///
/// ## Channel: "com.cyberguard.security/player"
class SecurePlayerPluginMacOS: NSObject, FlutterPlugin {

    static let channelName = "com.cyberguard.security/player"

    private var methodChannel: FlutterMethodChannel?
    private var textureRegistry: FlutterTextureRegistry?

    /// Active player instances (playerId → PlayerInstance)
    private var players: [String: MacOSPlayerInstance] = [:]

    override init() {
        self.methodChannel = nil
        self.textureRegistry = nil
        super.init()
    }

    // MARK: - FlutterPlugin

    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: channelName,
            binaryMessenger: registrar.messenger
        )
        let instance = SecurePlayerPluginMacOS()
        instance.methodChannel = channel
        instance.textureRegistry = registrar.textures
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
            result(FlutterError(code: "NO_REGISTRY", message: "Texture registry unavailable", details: nil))
            return
        }

        guard let args = call.arguments as? [String: Any],
              let sourceMap = args["source"] as? [String: Any] else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing source", details: nil))
            return
        }

        let configMap = args["config"] as? [String: Any]
        let playerId = UUID().uuidString

        // Build AVPlayerItem from source
        guard let playerItem = buildPlayerItem(from: sourceMap) else {
            result(FlutterError(code: "INVALID_SOURCE", message: "Could not create media item", details: nil))
            return
        }

        // Create AVPlayer
        let avPlayer = AVPlayer(playerItem: playerItem)

        // Apply config
        if let config = configMap {
            avPlayer.volume = Float(config["volume"] as? Double ?? 1.0)
            avPlayer.rate = Float(config["speed"] as? Double ?? 1.0)
        }

        // Create pixel buffer output
        let videoOutput = AVPlayerItemVideoOutput(pixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
        ])
        playerItem.add(videoOutput)

        // Create Flutter texture
        let textureRenderer = MacOSPlayerTextureRenderer(videoOutput: videoOutput)
        let textureId = registry.register(textureRenderer)

        // Store instance
        let instance = MacOSPlayerInstance(
            playerId: playerId,
            avPlayer: avPlayer,
            playerItem: playerItem,
            videoOutput: videoOutput,
            textureRenderer: textureRenderer,
            textureId: textureId,
            textureRegistry: registry
        )
        players[playerId] = instance

        // Use a timer for frame delivery on macOS (simpler than CVDisplayLink)
        instance.startFrameDelivery()

        // Observe player events
        instance.observeEvents { [weak self] event, data in
            self?.sendToFlutter(event, data: data, playerId: playerId)
        }

        // Auto-play if configured
        if configMap?["autoPlay"] as? Bool == true {
            avPlayer.play()
        }

        result([
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
            bufferedMs = Int((CMTimeGetSeconds(range.start) + CMTimeGetSeconds(range.duration)) * 1000)
        }

        result([
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

    private func getPlayer(_ call: FlutterMethodCall, result: @escaping FlutterResult) -> MacOSPlayerInstance? {
        let args = call.arguments as? [String: Any]
        guard let playerId = args?["playerId"] as? String,
              let player = players[playerId] else {
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

// MARK: - macOS Player Texture Renderer

class MacOSPlayerTextureRenderer: NSObject, FlutterTexture {
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

    func updateFrame() {
        let time = videoOutput.itemTime(forHostTime: CACurrentMediaTime())
        if videoOutput.hasNewPixelBuffer(forItemTime: time) {
            lastPixelBuffer = videoOutput.copyPixelBuffer(forItemTime: time, itemTimeForDisplay: nil)
        }
    }
}

// MARK: - macOS Player Instance

private class MacOSPlayerInstance {
    let playerId: String
    let avPlayer: AVPlayer
    let playerItem: AVPlayerItem
    let videoOutput: AVPlayerItemVideoOutput
    let textureRenderer: MacOSPlayerTextureRenderer
    let textureId: Int64
    let textureRegistry: FlutterTextureRegistry

    private var statusObservation: NSKeyValueObservation?
    private var timeObserver: Any?
    private var didEndObserver: NSObjectProtocol?
    private var frameTimer: Timer?

    init(
        playerId: String,
        avPlayer: AVPlayer,
        playerItem: AVPlayerItem,
        videoOutput: AVPlayerItemVideoOutput,
        textureRenderer: MacOSPlayerTextureRenderer,
        textureId: Int64,
        textureRegistry: FlutterTextureRegistry
    ) {
        self.playerId = playerId
        self.avPlayer = avPlayer
        self.playerItem = playerItem
        self.videoOutput = videoOutput
        self.textureRenderer = textureRenderer
        self.textureId = textureId
        self.textureRegistry = textureRegistry
    }

    func startFrameDelivery() {
        // 60 FPS frame delivery timer
        frameTimer = Timer.scheduledTimer(withTimeInterval: 1.0 / 60.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.textureRenderer.updateFrame()
            self.textureRegistry.textureFrameAvailable(self.textureId)
        }
    }

    func observeEvents(callback: @escaping (String, [String: Any]) -> Void) {
        // Observe playback status
        statusObservation = playerItem.observe(\.status, options: [.new]) { item, _ in
            switch item.status {
            case .readyToPlay:
                let duration = CMTimeGetSeconds(item.duration)
                let tracks = item.tracks.compactMap { $0.assetTrack }
                let videoTrack = tracks.first { $0.mediaType == .video }
                let size = videoTrack?.naturalSize ?? .zero
                callback("onReady", [
                    "durationMs": Int(duration * 1000),
                    "videoWidth": Int(size.width),
                    "videoHeight": Int(size.height),
                ])
            case .failed:
                callback("onError", [
                    "message": item.error?.localizedDescription ?? "Playback failed",
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
    }

    func release() {
        frameTimer?.invalidate()
        frameTimer = nil
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
