import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Platform DRM integration for hardware-backed content protection.
///
/// ## Why DRM matters for content protection:
///
/// Our custom AES-256-GCM encryption protects content at rest and in transit.
/// But once decrypted in memory, the content is vulnerable to extraction.
///
/// Platform DRM (Widevine, FairPlay) provides hardware-level protection:
/// the content is decrypted INSIDE the TEE/Secure Enclave, rendered directly
/// to a secure video pipeline, and NEVER exposed as plaintext in app memory.
///
/// ## Platform DRM systems:
///
/// ### Android: Widevine (via MediaDrm API)
/// - L1: Hardware-backed decryption + secure video path (TEE)
/// - L3: Software-only decryption (fallback for non-TEE devices)
/// - License server URL and content key IDs are managed server-side
///
/// ### iOS/macOS: FairPlay Streaming (via AVContentKeySession)
/// - SPC (Server Playback Context) generated on-device
/// - CKC (Content Key Context) returned from key server
/// - Keys stored in Secure Enclave, content decrypted in hardware
///
/// ### Web: Encrypted Media Extensions (EME)
/// - requestMediaKeySystemAccess() → Widevine or FairPlay
/// - MediaKeys → MediaKeySession → license exchange
/// - Handled by security_guard.js and browser CDM
///
/// ## Architecture:
/// ```
/// DrmBridge (Dart)
///     ↓ MethodChannel
///     ├── Android: MediaDrm → Widevine CDM → TEE
///     ├── iOS/macOS: AVContentKeySession → FairPlay → Secure Enclave
///     └── Web: EME API → Browser CDM
/// ```
///
/// ## License lifecycle:
/// ```
/// 1. requestLicense(contentId, serverUrl)
///     ↓
/// 2. Native generates challenge (SPC/Widevine request)
///     ↓
/// 3. App sends challenge to license server
///     ↓
/// 4. Server returns license (CKC/Widevine response)
///     ↓
/// 5. processLicenseResponse(contentId, response)
///     ↓
/// 6. Native stores key in TEE/Secure Enclave
///     ↓
/// 7. Content plays with hardware-decrypted video path
///     ↓
/// 8. releaseLicense(contentId) when session ends
/// ```
class DrmBridge {
  DrmBridge._();

  static final DrmBridge instance = DrmBridge._();

  /// MethodChannel for native DRM operations.
  ///
  /// Native side handles:
  /// - 'getDrmInfo': Returns DRM capabilities (system, level, hdcp)
  /// - 'createSession': Create a DRM session for a content ID
  /// - 'generateChallenge': Generate license request data
  /// - 'processResponse': Process license server response
  /// - 'releaseSession': Release a DRM session
  /// - 'releaseAll': Release all active DRM sessions
  static const _channel = MethodChannel('com.cyberguard.security/drm');

  /// Active DRM sessions, keyed by content ID.
  final Map<String, DrmSession> _sessions = {};

  /// Cached DRM system info (queried once on first use).
  DrmInfo? _cachedInfo;

  /// Get the platform DRM capabilities.
  ///
  /// Returns info about which DRM system is available, the security level,
  /// HDCP support, etc. Results are cached after the first call.
  ///
  /// On web: Returns EME availability from the browser.
  /// On unsupported platforms: Returns [DrmInfo.unavailable].
  Future<DrmInfo> getDrmInfo() async {
    if (_cachedInfo != null) return _cachedInfo!;

    if (kIsWeb) {
      // Web EME detection would go through the JS bridge.
      // For now, report basic availability.
      _cachedInfo = const DrmInfo(
        system: DrmSystem.eme,
        securityLevel: 'browser-managed',
        isAvailable: true,
      );
      return _cachedInfo!;
    }

    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'getDrmInfo',
      );
      if (result == null) {
        _cachedInfo = DrmInfo.unavailable;
        return _cachedInfo!;
      }

      _cachedInfo = DrmInfo(
        system: _parseDrmSystem(result['system'] as String? ?? ''),
        securityLevel: result['securityLevel'] as String? ?? 'unknown',
        isAvailable: result['isAvailable'] as bool? ?? false,
        maxHdcpLevel: result['maxHdcpLevel'] as String?,
        requiresSecureDecoder:
            result['requiresSecureDecoder'] as bool? ?? false,
      );
      return _cachedInfo!;
    } on MissingPluginException {
      _cachedInfo = DrmInfo.unavailable;
      return _cachedInfo!;
    } catch (e) {
      debugPrint('CyberGuard: DRM info query failed: $e');
      _cachedInfo = DrmInfo.unavailable;
      return _cachedInfo!;
    }
  }

  /// Create a DRM session and generate a license challenge.
  ///
  /// [contentId] — Unique identifier for the protected content.
  /// [licenseServerUrl] — URL of the license/key server.
  /// [contentKeyIds] — DRM key IDs embedded in the content manifest.
  ///
  /// Returns a [DrmChallenge] containing the binary data that must
  /// be sent to the license server. The app is responsible for the
  /// HTTP request to the license server.
  ///
  /// Returns null if the DRM system is unavailable or session creation fails.
  Future<DrmChallenge?> requestLicense({
    required String contentId,
    required String licenseServerUrl,
    List<String>? contentKeyIds,
  }) async {
    if (kIsWeb) {
      // Web EME handled by browser — return placeholder.
      return null;
    }

    try {
      // Step 1: Create DRM session on native side
      await _channel.invokeMethod<void>('createSession', {
        'contentId': contentId,
        'licenseServerUrl': licenseServerUrl,
        'contentKeyIds': ?contentKeyIds,
      });

      // Step 2: Generate the license challenge (SPC/Widevine request)
      final challengeBytes = await _channel.invokeMethod<Uint8List>(
        'generateChallenge',
        {'contentId': contentId},
      );

      if (challengeBytes == null) return null;

      final session = DrmSession(
        contentId: contentId,
        licenseServerUrl: licenseServerUrl,
        state: DrmSessionState.pendingLicense,
        createdAt: DateTime.now(),
      );
      _sessions[contentId] = session;

      return DrmChallenge(
        contentId: contentId,
        challengeData: challengeBytes,
        licenseServerUrl: licenseServerUrl,
      );
    } on MissingPluginException {
      debugPrint('CyberGuard: DRM not available on this platform.');
      return null;
    } catch (e) {
      debugPrint('CyberGuard: License request failed: $e');
      return null;
    }
  }

  /// Process the license server response.
  ///
  /// After the app sends the challenge to the license server and receives
  /// a response, pass the response bytes here. The native side will:
  /// 1. Parse the license/key
  /// 2. Store the content key in TEE/Secure Enclave
  /// 3. Make the key available for hardware-backed decryption
  ///
  /// Returns true if the license was accepted and content is ready to play.
  Future<bool> processLicenseResponse({
    required String contentId,
    required Uint8List responseData,
  }) async {
    if (kIsWeb) return false;

    try {
      final success = await _channel.invokeMethod<bool>('processResponse', {
        'contentId': contentId,
        'responseData': responseData,
      });

      if (success == true) {
        _sessions[contentId] =
            _sessions[contentId]?.copyWithState(DrmSessionState.active) ??
            DrmSession(
              contentId: contentId,
              licenseServerUrl: '',
              state: DrmSessionState.active,
              createdAt: DateTime.now(),
            );
      }

      return success ?? false;
    } on MissingPluginException {
      return false;
    } catch (e) {
      debugPrint('CyberGuard: License response processing failed: $e');
      return false;
    }
  }

  /// Release a DRM session for a specific content.
  ///
  /// Call when the user stops viewing protected content.
  /// The native side will:
  /// 1. Release the content key from TEE/Secure Enclave
  /// 2. Close the DRM session
  /// 3. Free native resources
  Future<void> releaseLicense(String contentId) async {
    _sessions.remove(contentId);

    if (kIsWeb) return;

    try {
      await _channel.invokeMethod<void>('releaseSession', {
        'contentId': contentId,
      });
    } on MissingPluginException {
      // Silently ignore.
    } catch (e) {
      debugPrint('CyberGuard: License release failed: $e');
    }
  }

  /// Release ALL active DRM sessions.
  ///
  /// Call on logout or app termination.
  /// Nuclear option — drops all content keys from device hardware.
  Future<void> releaseAll() async {
    _sessions.clear();

    if (kIsWeb) return;

    try {
      await _channel.invokeMethod<void>('releaseAll');
    } on MissingPluginException {
      // Silently ignore.
    }
  }

  /// Get active DRM sessions.
  Map<String, DrmSession> get activeSessions => Map.unmodifiable(_sessions);

  // ─── Private ───

  DrmSystem _parseDrmSystem(String value) {
    switch (value) {
      case 'widevine':
        return DrmSystem.widevine;
      case 'fairplay':
        return DrmSystem.fairplay;
      case 'eme':
        return DrmSystem.eme;
      default:
        return DrmSystem.none;
    }
  }
}

/// Platform DRM system identifier.
enum DrmSystem {
  /// Google Widevine (Android).
  widevine,

  /// Apple FairPlay Streaming (iOS/macOS).
  fairplay,

  /// W3C Encrypted Media Extensions (Web).
  eme,

  /// No DRM available.
  none,
}

/// State of a DRM session.
enum DrmSessionState {
  /// Session created, waiting for license challenge generation.
  pendingChallenge,

  /// Challenge generated, waiting for license server response.
  pendingLicense,

  /// License acquired, content key active in TEE/Secure Enclave.
  active,

  /// License expired, needs renewal.
  expired,

  /// Session released, key removed from hardware.
  released,
}

/// Information about the platform DRM capabilities.
class DrmInfo {
  const DrmInfo({
    required this.system,
    required this.securityLevel,
    required this.isAvailable,
    this.maxHdcpLevel,
    this.requiresSecureDecoder = false,
  });

  /// Sentinel for unavailable DRM.
  static const DrmInfo unavailable = DrmInfo(
    system: DrmSystem.none,
    securityLevel: 'none',
    isAvailable: false,
  );

  /// Which DRM system is available on this platform.
  final DrmSystem system;

  /// Security level string.
  ///
  /// Widevine: "L1" (hardware), "L2" (partial), "L3" (software-only)
  /// FairPlay: "hardware" or "software"
  final String securityLevel;

  /// Whether DRM is available at all.
  final bool isAvailable;

  /// Maximum HDCP level supported (e.g., "2.2", "1.4").
  ///
  /// null if HDCP query is not supported on this platform.
  final String? maxHdcpLevel;

  /// Whether the device requires a secure decoder for protected content.
  ///
  /// If true, only hardware video decoders in the TEE can process the
  /// decrypted content. Software decoders are blocked.
  final bool requiresSecureDecoder;

  /// Whether the device has hardware-backed DRM (L1/hardware).
  bool get isHardwareBacked =>
      securityLevel == 'L1' || securityLevel == 'hardware';

  @override
  String toString() =>
      'DrmInfo(${system.name}, level=$securityLevel, available=$isAvailable)';
}

/// License challenge data to send to the license server.
class DrmChallenge {
  const DrmChallenge({
    required this.contentId,
    required this.challengeData,
    required this.licenseServerUrl,
  });

  /// Content being licensed.
  final String contentId;

  /// Binary challenge data (SPC for FairPlay, Widevine request proto).
  ///
  /// Send this as the HTTP POST body to the license server.
  final Uint8List challengeData;

  /// License server URL to send the challenge to.
  final String licenseServerUrl;
}

/// Tracks an active DRM session.
class DrmSession {
  const DrmSession({
    required this.contentId,
    required this.licenseServerUrl,
    required this.state,
    required this.createdAt,
  });

  final String contentId;
  final String licenseServerUrl;
  final DrmSessionState state;
  final DateTime createdAt;

  DrmSession copyWithState(DrmSessionState newState) {
    return DrmSession(
      contentId: contentId,
      licenseServerUrl: licenseServerUrl,
      state: newState,
      createdAt: createdAt,
    );
  }
}
