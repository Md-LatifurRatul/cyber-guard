import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Custom TLS certificate pinning without third-party packages.
///
/// ## Why certificate pinning:
///
/// HTTPS protects against passive eavesdropping, but NOT against active MITM
/// where the attacker controls a trusted CA (corporate proxy, Burp Suite,
/// Charles Proxy, mitmproxy). These tools install a custom CA certificate
/// on the device, then generate fake certificates for any domain.
///
/// With pinning, the app embeds the expected SHA-256 hash of the server's
/// public key (SPKI). Even with a rogue CA installed, the server's real
/// public key doesn't match the pin → connection rejected.
///
/// ## How it works:
///
/// ```
/// App sends HTTPS request
///     ↓
/// TLS handshake begins
///     ↓
/// Server presents certificate chain
///     ↓
/// CertificatePinner extracts SPKI hash from leaf/intermediate
///     ↓
/// Compares against pinned SHA-256 hashes
///     ↓
/// Match → connection proceeds
/// No match → connection terminated, SecurityEvent fired
/// ```
///
/// ## Pin rotation:
///
/// Always pin at least 2 keys per host:
/// - Current server certificate's SPKI hash
/// - Backup/next certificate's SPKI hash
///
/// This allows certificate rotation without breaking pinning.
/// If you only pin one key and the certificate rotates, all clients break.
///
/// ## Platform behavior:
///
/// | Platform | Mechanism                    | Pinning possible? |
/// |----------|------------------------------|-------------------|
/// | Android  | OkHttp CertificatePinner     | Yes               |
/// | iOS      | URLSession delegate          | Yes               |
/// | macOS    | URLSession delegate          | Yes               |
/// | Web      | Browser controls TLS         | No (limitation)   |
///
/// ## Getting the pin hash:
///
/// ```bash
/// # Extract SPKI SHA-256 from a live server:
/// openssl s_client -connect example.com:443 2>/dev/null | \
///   openssl x509 -pubkey -noout | \
///   openssl pkey -pubin -outform DER | \
///   openssl dgst -sha256 -binary | base64
/// ```
class CertificatePinner {
  CertificatePinner._();

  static final CertificatePinner instance = CertificatePinner._();

  /// MethodChannel for native TLS pin verification.
  ///
  /// Native side handles:
  /// - 'configurePins': Set pinned hosts and their SHA-256 SPKI hashes
  /// - 'validateCertificate': Check a certificate chain against pins
  /// - 'clearPins': Remove all pinning rules
  static const _channel =
      MethodChannel('com.cyberguard.security/certpin');

  /// Pinned hosts and their allowed SPKI hashes.
  ///
  /// Key: hostname (e.g., "api.example.com")
  /// Value: Set of base64-encoded SHA-256 SPKI hashes
  final Map<String, Set<String>> _pins = {};

  /// Callback invoked when a pin validation fails.
  ///
  /// Use this to fire a SecurityEvent, log the failure, and terminate
  /// the connection. The map contains:
  /// - 'host': The hostname that failed
  /// - 'expectedPins': List of pinned hashes
  /// - 'actualHash': The hash of the server's certificate (if available)
  void Function(Map<String, dynamic> failure)? onPinFailure;

  bool _configured = false;

  /// Whether pinning is available on this platform.
  ///
  /// False on web (browser controls TLS — no access to certificate chain).
  bool get isAvailable => !kIsWeb;

  /// Configure certificate pins for one or more hosts.
  ///
  /// [pins] maps hostnames to their trusted SPKI SHA-256 hashes.
  /// Each hash must be a base64-encoded SHA-256 digest of the certificate's
  /// Subject Public Key Info (SPKI) in DER format.
  ///
  /// Always include at least 2 hashes per host (current + backup) to
  /// survive certificate rotation.
  ///
  /// Example:
  /// ```dart
  /// await CertificatePinner.instance.configure({
  ///   'api.example.com': {
  ///     'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // current
  ///     'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', // backup
  ///   },
  /// });
  /// ```
  Future<void> configure(Map<String, Set<String>> pins) async {
    _pins.clear();
    for (final entry in pins.entries) {
      // Strip 'sha256/' prefix if present (convenience)
      final cleaned = entry.value
          .map((h) => h.startsWith('sha256/') ? h.substring(7) : h)
          .toSet();
      _pins[entry.key] = cleaned;
    }

    if (!kIsWeb) {
      try {
        // Send pins to native side for TLS-level enforcement
        final serialized = _pins.map(
          (host, hashes) => MapEntry(host, hashes.toList()),
        );
        await _channel.invokeMethod<void>('configurePins', {
          'pins': serialized,
        });
      } on MissingPluginException {
        debugPrint('CyberGuard: Native certificate pinning not available.');
      }
    }

    _configured = true;
  }

  /// Validate a certificate's SPKI hash against pinned values.
  ///
  /// [host] — The hostname being connected to.
  /// [certificateHash] — Base64-encoded SHA-256 of the certificate's SPKI.
  ///
  /// Returns true if the hash matches a pinned value, or if no pins
  /// are configured for this host (pass-through for unpinned hosts).
  ///
  /// On native platforms, this is called automatically by the native
  /// TLS stack during the handshake. On Dart side, this can be used
  /// for manual verification (e.g., with custom HTTP clients).
  bool validate(String host, String certificateHash) {
    final hostPins = _pins[host];

    // No pins for this host → pass through (don't break non-pinned hosts)
    if (hostPins == null || hostPins.isEmpty) return true;

    final clean =
        certificateHash.startsWith('sha256/')
            ? certificateHash.substring(7)
            : certificateHash;

    if (hostPins.contains(clean)) return true;

    // Pin mismatch — potential MITM
    onPinFailure?.call({
      'host': host,
      'expectedPins': hostPins.toList(),
      'actualHash': clean,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    });

    return false;
  }

  /// Get all pinned hosts.
  Set<String> get pinnedHosts => _pins.keys.toSet();

  /// Check if a specific host has pins configured.
  bool isPinned(String host) => _pins.containsKey(host);

  /// Add pins for a host at runtime (e.g., from server config).
  ///
  /// Useful for dynamic pin configuration where the initial pins
  /// come from a hardcoded fallback but can be updated from the server.
  void addPins(String host, Set<String> hashes) {
    final existing = _pins[host] ?? {};
    _pins[host] = existing.union(hashes);
  }

  /// Remove all pins and disable pinning.
  ///
  /// Call on debug builds or when pinning needs to be temporarily disabled.
  Future<void> clearAll() async {
    _pins.clear();
    _configured = false;

    if (!kIsWeb) {
      try {
        await _channel.invokeMethod<void>('clearPins');
      } on MissingPluginException {
        // Silently ignore.
      }
    }
  }

  /// Whether any pins are configured.
  bool get isConfigured => _configured && _pins.isNotEmpty;

  /// Serialize pins to JSON for storage or transmission.
  String toJson() {
    final map = _pins.map((k, v) => MapEntry(k, v.toList()));
    return jsonEncode(map);
  }

  /// Load pins from JSON (e.g., from embedded asset or remote config).
  ///
  /// Useful for loading pins from a signed configuration file
  /// rather than hardcoding them in source code.
  Future<void> fromJson(String json) async {
    final decoded = jsonDecode(json) as Map<String, dynamic>;
    final pins = decoded.map(
      (k, v) => MapEntry(k, (v as List).cast<String>().toSet()),
    );
    await configure(pins);
  }
}
