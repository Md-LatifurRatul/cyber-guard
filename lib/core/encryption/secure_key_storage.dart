import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Platform-specific secure key storage abstraction.
///
/// ## Why not just store keys in SharedPreferences:
///
/// SharedPreferences stores data as **plaintext XML/plist** on disk.
/// On a rooted/jailbroken device, any app (or the user) can read it.
/// Encryption keys stored there are trivially extractable.
///
/// ## Platform implementations:
///
/// ### Android: AndroidKeyStore
/// Keys are stored in a hardware-backed keystore (TEE/StrongBox).
/// Even root access cannot extract the key material — the hardware
/// performs crypto operations without exposing the raw key.
/// We store content keys encrypted by a KeyStore master key.
///
/// ### iOS/macOS: Keychain Services
/// The Keychain encrypts items with a key derived from the device
/// passcode and hardware UID. Items can be marked as requiring
/// biometric authentication to access.
/// We store content keys as Keychain generic password items.
///
/// ### Web: In-memory only
/// Web has no secure persistent storage. Keys exist only in JS memory
/// for the session duration. When the tab closes, keys are gone.
/// The server must re-issue keys for each session.
///
/// ## Architecture:
/// ```
/// ContentEncryptor
///     ↓ needs key
/// SecureKeyStorage
///     ↓ platform dispatch
///     ├── Android: KeyStore → TEE/StrongBox
///     ├── iOS/macOS: Keychain → Secure Enclave
///     └── Web: JavaScript Map (session only)
/// ```
class SecureKeyStorage {
  SecureKeyStorage._();

  static final SecureKeyStorage instance = SecureKeyStorage._();

  /// MethodChannel for native key storage operations.
  ///
  /// On Android: Calls KeyStore wrapper in Kotlin.
  /// On iOS/macOS: Calls Keychain wrapper in Swift.
  /// On web: Falls back to in-memory storage (no native).
  static const _channel = MethodChannel('com.cyberguard.security/keystore');

  /// In-memory fallback for web and when native storage fails.
  final Map<String, Uint8List> _memoryStore = {};

  /// Store a content encryption key securely.
  ///
  /// [keyId] — Unique identifier for this key (e.g., content ID).
  /// [key] — The raw AES-256 key bytes (32 bytes).
  ///
  /// On native platforms, the key is encrypted by the platform's
  /// hardware-backed master key before storage. On web, it stays
  /// in memory only.
  Future<bool> storeKey(String keyId, Uint8List key) async {
    if (kIsWeb) {
      _memoryStore[keyId] = Uint8List.fromList(key);
      return true;
    }

    try {
      await _channel.invokeMethod<void>('storeKey', {
        'keyId': keyId,
        'key': base64Encode(key),
      });
      return true;
    } on MissingPluginException {
      // Native key storage not available — fall back to memory.
      _memoryStore[keyId] = Uint8List.fromList(key);
      return true;
    } catch (e) {
      debugPrint('CyberGuard: Failed to store key: $e');
      return false;
    }
  }

  /// Retrieve a content encryption key.
  ///
  /// Returns null if the key doesn't exist or retrieval fails.
  /// On native platforms, the key is decrypted by the platform's
  /// hardware-backed master key before being returned.
  Future<Uint8List?> retrieveKey(String keyId) async {
    if (kIsWeb) {
      return _memoryStore[keyId];
    }

    try {
      final result = await _channel.invokeMethod<String>('retrieveKey', {
        'keyId': keyId,
      });
      if (result == null) return null;
      return base64Decode(result);
    } on MissingPluginException {
      // Native key storage not available — check memory.
      return _memoryStore[keyId];
    } catch (e) {
      debugPrint('CyberGuard: Failed to retrieve key: $e');
      return null;
    }
  }

  /// Delete a content encryption key.
  ///
  /// Call when content access is revoked or the session ends.
  /// On native platforms, removes from hardware keystore.
  Future<bool> deleteKey(String keyId) async {
    _memoryStore.remove(keyId);

    if (kIsWeb) return true;

    try {
      await _channel.invokeMethod<void>('deleteKey', {
        'keyId': keyId,
      });
      return true;
    } on MissingPluginException {
      return true;
    } catch (e) {
      debugPrint('CyberGuard: Failed to delete key: $e');
      return false;
    }
  }

  /// Clear all stored keys.
  ///
  /// Call on logout or session termination.
  /// Nuclear option — removes ALL content keys from the device.
  Future<void> clearAll() async {
    // Zero all in-memory keys before removing
    for (final key in _memoryStore.values) {
      key.fillRange(0, key.length, 0);
    }
    _memoryStore.clear();

    if (kIsWeb) return;

    try {
      await _channel.invokeMethod<void>('clearAllKeys');
    } on MissingPluginException {
      // No native storage to clear.
    }
  }
}
