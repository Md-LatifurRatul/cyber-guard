/// Dart FFI bindings for the CyberGuard Rust core library.
///
/// ## How dart:ffi works:
///
/// 1. `DynamicLibrary.open()` loads the compiled Rust library at runtime
/// 2. `lookup<NativeFunction<...>>()` finds a C function by name
/// 3. `.asFunction<...>()` converts it to a callable Dart function
/// 4. We call it just like a normal Dart function — zero platform channel overhead
///
/// ## Library naming per platform:
/// - Android: `libcyberguard_core.so` (loaded via JNI)
/// - iOS: Statically linked into the app binary (no separate .dylib)
/// - macOS: `libcyberguard_core.dylib` (bundled in app)
/// - Web: `cyberguard_core.wasm` (loaded via dart:wasm in Phase 8)
///
/// ## Memory management:
/// Rust functions write into Dart-allocated buffers (via `calloc`).
/// We always `calloc.free()` after use to prevent memory leaks.
/// No Rust-allocated memory crosses the FFI boundary (except version string
/// which is a static constant).
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Loads and provides access to all CyberGuard Rust FFI functions.
///
/// Usage:
/// ```dart
/// final bridge = NativeBridge.instance;
/// final result = bridge.encodeWatermark(pixels, userId, timestamp, sessionId);
/// ```
class NativeBridge {
  NativeBridge._() {
    _lib = _loadLibrary();
    _bindFunctions();
  }

  static NativeBridge? _instance;

  /// Singleton instance. Loads the library on first access.
  static NativeBridge get instance => _instance ??= NativeBridge._();

  /// Whether the native library was loaded successfully.
  static bool get isAvailable {
    try {
      instance; // Force load
      return true;
    } catch (_) {
      return false;
    }
  }

  late final ffi.DynamicLibrary _lib;

  // -- Bound function pointers --

  // Watermark
  late final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
  ) _watermarkEncode;

  late final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint64>,
    ffi.Pointer<ffi.Uint8>,
  ) _watermarkDecode;

  late final int Function() _watermarkMinPixels;

  // Crypto
  late final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
  ) _encrypt;

  late final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
  ) _decrypt;

  late final int Function(ffi.Pointer<ffi.Uint8>) _generateKey;

  late final int Function() _encryptionOverhead;

  // Detection
  late final int Function(ffi.Pointer<Utf8>) _isCaptureProcess;
  late final int Function(ffi.Pointer<Utf8>) _isHookSignature;
  late final int Function(ffi.Pointer<ffi.Uint8>, int) _computeChecksum64;
  late final int Function(ffi.Pointer<ffi.Uint8>, int, int) _verifyChecksum;

  // Utility
  late final ffi.Pointer<Utf8> Function() _version;

  // ============================================================================
  // PUBLIC API — Watermark
  // ============================================================================

  /// Encode a steganographic watermark into RGBA pixel data.
  ///
  /// [pixels] is modified in-place. Must be RGBA format (4 bytes per pixel).
  /// [userId] must be exactly 32 bytes (SHA-256 hash of user email).
  /// [timestampMs] is Unix timestamp in milliseconds.
  /// [sessionId] must be exactly 12 bytes.
  ///
  /// Returns 0 on success, negative error code on failure.
  int encodeWatermark(
    Uint8List pixels,
    Uint8List userId,
    int timestampMs,
    Uint8List sessionId,
  ) {
    assert(userId.length == 32, 'userId must be 32 bytes');
    assert(sessionId.length == 12, 'sessionId must be 12 bytes');

    final pixelCount = pixels.length ~/ 4;

    final pPixels = calloc<ffi.Uint8>(pixels.length);
    final pUserId = calloc<ffi.Uint8>(32);
    final pSessionId = calloc<ffi.Uint8>(12);

    try {
      // Copy data to native memory
      pPixels.asTypedList(pixels.length).setAll(0, pixels);
      pUserId.asTypedList(32).setAll(0, userId);
      pSessionId.asTypedList(12).setAll(0, sessionId);

      final result = _watermarkEncode(
        pPixels,
        pixelCount,
        pUserId,
        timestampMs,
        pSessionId,
      );

      // Copy modified pixels back
      if (result == 0) {
        pixels.setAll(0, pPixels.asTypedList(pixels.length));
      }

      return result;
    } finally {
      calloc.free(pPixels);
      calloc.free(pUserId);
      calloc.free(pSessionId);
    }
  }

  /// Decode a steganographic watermark from RGBA pixel data.
  ///
  /// Returns a [WatermarkData] on success, or null if no valid watermark found.
  WatermarkData? decodeWatermark(Uint8List pixels) {
    final pixelCount = pixels.length ~/ 4;

    final pPixels = calloc<ffi.Uint8>(pixels.length);
    final pUserId = calloc<ffi.Uint8>(32);
    final pTimestamp = calloc<ffi.Uint64>(1);
    final pSessionId = calloc<ffi.Uint8>(12);

    try {
      pPixels.asTypedList(pixels.length).setAll(0, pixels);

      final result = _watermarkDecode(
        pPixels,
        pixelCount,
        pUserId,
        pTimestamp,
        pSessionId,
      );

      if (result != 0) return null;

      return WatermarkData(
        userId: Uint8List.fromList(pUserId.asTypedList(32)),
        timestampMs: pTimestamp.value,
        sessionId: Uint8List.fromList(pSessionId.asTypedList(12)),
      );
    } finally {
      calloc.free(pPixels);
      calloc.free(pUserId);
      calloc.free(pTimestamp);
      calloc.free(pSessionId);
    }
  }

  /// Minimum number of pixels needed for watermark encoding.
  int get watermarkMinPixels => _watermarkMinPixels();

  // ============================================================================
  // PUBLIC API — Crypto
  // ============================================================================

  /// Encrypt data using AES-256-GCM.
  ///
  /// [key] must be exactly 32 bytes.
  /// Returns encrypted bytes (nonce + ciphertext + tag), or null on failure.
  Uint8List? encrypt(Uint8List key, Uint8List plaintext) {
    assert(key.length == 32, 'Key must be 32 bytes');

    final overhead = _encryptionOverhead();
    final outputSize = plaintext.length + overhead;

    final pKey = calloc<ffi.Uint8>(32);
    final pPlaintext = calloc<ffi.Uint8>(plaintext.length);
    final pOutput = calloc<ffi.Uint8>(outputSize);

    try {
      pKey.asTypedList(32).setAll(0, key);
      pPlaintext.asTypedList(plaintext.length).setAll(0, plaintext);

      final result = _encrypt(
        pKey,
        pPlaintext,
        plaintext.length,
        pOutput,
        outputSize,
      );

      if (result <= 0) return null;

      return Uint8List.fromList(pOutput.asTypedList(result));
    } finally {
      calloc.free(pKey);
      calloc.free(pPlaintext);
      calloc.free(pOutput);
    }
  }

  /// Decrypt data encrypted with AES-256-GCM.
  ///
  /// [key] must be exactly 32 bytes.
  /// Returns decrypted bytes, or null on failure (wrong key or tampered data).
  Uint8List? decrypt(Uint8List key, Uint8List encrypted) {
    assert(key.length == 32, 'Key must be 32 bytes');

    final overhead = _encryptionOverhead();
    if (encrypted.length < overhead) return null;

    final outputSize = encrypted.length - overhead;

    final pKey = calloc<ffi.Uint8>(32);
    final pEncrypted = calloc<ffi.Uint8>(encrypted.length);
    final pOutput = calloc<ffi.Uint8>(outputSize > 0 ? outputSize : 1);

    try {
      pKey.asTypedList(32).setAll(0, key);
      pEncrypted.asTypedList(encrypted.length).setAll(0, encrypted);

      final result = _decrypt(
        pKey,
        pEncrypted,
        encrypted.length,
        pOutput,
        outputSize > 0 ? outputSize : 1,
      );

      if (result < 0) return null;

      return Uint8List.fromList(pOutput.asTypedList(result));
    } finally {
      calloc.free(pKey);
      calloc.free(pEncrypted);
      calloc.free(pOutput);
    }
  }

  /// Generate a cryptographically secure 256-bit key.
  Uint8List generateKey() {
    final pKey = calloc<ffi.Uint8>(32);
    try {
      _generateKey(pKey);
      return Uint8List.fromList(pKey.asTypedList(32));
    } finally {
      calloc.free(pKey);
    }
  }

  /// Encryption overhead in bytes (nonce + auth tag = 28).
  int get encryptionOverhead => _encryptionOverhead();

  // ============================================================================
  // PUBLIC API — Detection
  // ============================================================================

  /// Check if a process name matches a known screen capture tool.
  bool isCaptureProcess(String processName) {
    final pName = processName.toNativeUtf8();
    try {
      return _isCaptureProcess(pName) == 1;
    } finally {
      calloc.free(pName);
    }
  }

  /// Check if a string contains hooking framework signatures.
  bool isHookSignature(String target) {
    final pTarget = target.toNativeUtf8();
    try {
      return _isHookSignature(pTarget) == 1;
    } finally {
      calloc.free(pTarget);
    }
  }

  /// Compute FNV-1a checksum over data.
  int computeChecksum(Uint8List data) {
    final pData = calloc<ffi.Uint8>(data.length);
    try {
      pData.asTypedList(data.length).setAll(0, data);
      return _computeChecksum64(pData, data.length);
    } finally {
      calloc.free(pData);
    }
  }

  /// Verify data integrity against a known checksum.
  bool verifyChecksum(Uint8List data, int expected) {
    final pData = calloc<ffi.Uint8>(data.length);
    try {
      pData.asTypedList(data.length).setAll(0, data);
      return _verifyChecksum(pData, data.length, expected) == 1;
    } finally {
      calloc.free(pData);
    }
  }

  // ============================================================================
  // PUBLIC API — Utility
  // ============================================================================

  /// Get the native library version string.
  String get nativeVersion => _version().toDartString();

  // ============================================================================
  // PRIVATE — Library Loading
  // ============================================================================

  static ffi.DynamicLibrary _loadLibrary() {
    if (Platform.isAndroid) {
      return ffi.DynamicLibrary.open('libcyberguard_core.so');
    }
    if (Platform.isMacOS) {
      return ffi.DynamicLibrary.open('libcyberguard_core.dylib');
    }
    if (Platform.isIOS) {
      // On iOS, Rust is statically linked — look up in the process
      return ffi.DynamicLibrary.process();
    }
    throw UnsupportedError(
      'CyberGuard native library not supported on ${Platform.operatingSystem}',
    );
  }

  // ============================================================================
  // PRIVATE — Function Binding
  // ============================================================================

  /// Expected native library version. Must match Rust Cargo.toml version.
  static const _expectedVersion = '0.1.0';

  void _bindFunctions() {
    // Bind version first and verify compatibility
    _version = _lib
        .lookupFunction<
          ffi.Pointer<Utf8> Function(),
          ffi.Pointer<Utf8> Function()
        >('cg_version');

    final nativeVer = _version().toDartString();
    if (nativeVer != _expectedVersion) {
      throw StateError(
        'CyberGuard native library version mismatch: '
        'Dart expects $_expectedVersion, native is $nativeVer',
      );
    }

    // Watermark
    _watermarkEncode = _lib
        .lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint64,
            ffi.Pointer<ffi.Uint8>,
          ),
          int Function(
            ffi.Pointer<ffi.Uint8>,
            int,
            ffi.Pointer<ffi.Uint8>,
            int,
            ffi.Pointer<ffi.Uint8>,
          )
        >('cg_watermark_encode');

    _watermarkDecode = _lib
        .lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint8>,
          ),
          int Function(
            ffi.Pointer<ffi.Uint8>,
            int,
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint64>,
            ffi.Pointer<ffi.Uint8>,
          )
        >('cg_watermark_decode');

    _watermarkMinPixels = _lib
        .lookupFunction<ffi.Uint32 Function(), int Function()>(
          'cg_watermark_min_pixels',
        );

    // Crypto
    _encrypt = _lib
        .lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
          ),
          int Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>,
            int,
            ffi.Pointer<ffi.Uint8>,
            int,
          )
        >('cg_encrypt');

    _decrypt = _lib
        .lookupFunction<
          ffi.Int32 Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
            ffi.Pointer<ffi.Uint8>,
            ffi.Uint32,
          ),
          int Function(
            ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>,
            int,
            ffi.Pointer<ffi.Uint8>,
            int,
          )
        >('cg_decrypt');

    _generateKey = _lib
        .lookupFunction<
          ffi.Int32 Function(ffi.Pointer<ffi.Uint8>),
          int Function(ffi.Pointer<ffi.Uint8>)
        >('cg_generate_key');

    _encryptionOverhead = _lib
        .lookupFunction<ffi.Uint32 Function(), int Function()>(
          'cg_encryption_overhead',
        );

    // Detection
    _isCaptureProcess = _lib
        .lookupFunction<
          ffi.Int32 Function(ffi.Pointer<Utf8>),
          int Function(ffi.Pointer<Utf8>)
        >('cg_is_capture_process');

    _isHookSignature = _lib
        .lookupFunction<
          ffi.Int32 Function(ffi.Pointer<Utf8>),
          int Function(ffi.Pointer<Utf8>)
        >('cg_is_hook_signature');

    _computeChecksum64 = _lib
        .lookupFunction<
          ffi.Uint64 Function(ffi.Pointer<ffi.Uint8>, ffi.Uint32),
          int Function(ffi.Pointer<ffi.Uint8>, int)
        >('cg_compute_checksum');

    _verifyChecksum = _lib
        .lookupFunction<
          ffi.Int32 Function(ffi.Pointer<ffi.Uint8>, ffi.Uint32, ffi.Uint64),
          int Function(ffi.Pointer<ffi.Uint8>, int, int)
        >('cg_verify_checksum');

    // _version already bound at top of _bindFunctions (version check)
  }
}

/// Decoded watermark data extracted from an image.
class WatermarkData {
  const WatermarkData({
    required this.userId,
    required this.timestampMs,
    required this.sessionId,
  });

  /// 32-byte user identifier (SHA-256 hash of email).
  final Uint8List userId;

  /// Unix timestamp in milliseconds when the watermark was embedded.
  final int timestampMs;

  /// 12-byte session identifier.
  final Uint8List sessionId;

  /// Convert user ID bytes to hex string for display.
  String get userIdHex =>
      userId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Convert session ID bytes to hex string.
  String get sessionIdHex =>
      sessionId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Timestamp as DateTime.
  DateTime get timestamp =>
      DateTime.fromMillisecondsSinceEpoch(timestampMs);
}
