import 'dart:typed_data';

/// Source descriptor for media content (video/audio).
///
/// Uses sealed class hierarchy so the type system enforces valid inputs.
/// Each variant carries only the data relevant to that source type.
///
/// ## Usage:
/// ```dart
/// // Network video (mp4, HLS, DASH, etc.)
/// MediaSource.network('https://example.com/video.mp4')
///
/// // Local asset bundled with the app
/// MediaSource.asset('assets/videos/intro.mp4')
///
/// // File on device storage
/// MediaSource.file('/data/user/0/com.app/files/video.mp4')
///
/// // Live stream (HLS, RTMP, DASH)
/// MediaSource.liveStream('https://stream.example.com/live.m3u8')
/// ```
sealed class MediaSource {
  const MediaSource();

  /// Network video/audio URL (mp4, webm, mkv, HLS .m3u8, DASH .mpd, etc.).
  const factory MediaSource.network(
    String url, {
    Map<String, String> headers,
  }) = NetworkMediaSource;

  /// Bundled asset from the Flutter asset bundle.
  const factory MediaSource.asset(String assetPath) = AssetMediaSource;

  /// File path on device storage.
  const factory MediaSource.file(String filePath) = FileMediaSource;

  /// Live stream URL (HLS, RTMP, DASH).
  ///
  /// Functionally similar to [NetworkMediaSource] but signals to the player
  /// that this is a live stream (no duration, no seek, live edge behavior).
  const factory MediaSource.liveStream(
    String url, {
    Map<String, String> headers,
  }) = LiveStreamMediaSource;

  /// Raw bytes in memory (e.g., decrypted content from ContentEncryptor).
  const factory MediaSource.memory(
    Uint8List bytes, {
    String mimeType,
  }) = MemoryMediaSource;
}

/// Video/audio loaded from a network URL.
class NetworkMediaSource extends MediaSource {
  const NetworkMediaSource(this.url, {this.headers = const {}});

  /// The network URL (HTTP/HTTPS).
  final String url;

  /// Optional HTTP headers (e.g., Authorization, Range).
  final Map<String, String> headers;
}

/// Video/audio loaded from a Flutter asset.
class AssetMediaSource extends MediaSource {
  const AssetMediaSource(this.assetPath);

  /// Asset path relative to project root (e.g., 'assets/videos/intro.mp4').
  final String assetPath;
}

/// Video/audio loaded from a file on device storage.
class FileMediaSource extends MediaSource {
  const FileMediaSource(this.filePath);

  /// Absolute file path on the device.
  final String filePath;
}

/// Live stream source (HLS, RTMP, DASH).
class LiveStreamMediaSource extends MediaSource {
  const LiveStreamMediaSource(this.url, {this.headers = const {}});

  /// The stream URL.
  final String url;

  /// Optional HTTP headers for authenticated streams.
  final Map<String, String> headers;
}

/// Video/audio loaded from raw bytes in memory.
class MemoryMediaSource extends MediaSource {
  const MemoryMediaSource(this.bytes, {this.mimeType = 'video/mp4'});

  /// Raw media bytes.
  final Uint8List bytes;

  /// MIME type hint for the player (e.g., 'video/mp4', 'audio/aac').
  final String mimeType;
}

/// Source descriptor for PDF documents.
///
/// ## Usage:
/// ```dart
/// PdfSource.network('https://example.com/report.pdf')
/// PdfSource.asset('assets/docs/manual.pdf')
/// PdfSource.file('/storage/downloads/contract.pdf')
/// PdfSource.memory(decryptedBytes)
/// ```
sealed class PdfSource {
  const PdfSource();

  /// PDF from a network URL.
  const factory PdfSource.network(
    String url, {
    Map<String, String> headers,
  }) = NetworkPdfSource;

  /// PDF bundled as a Flutter asset.
  const factory PdfSource.asset(String assetPath) = AssetPdfSource;

  /// PDF file on device storage.
  const factory PdfSource.file(String filePath) = FilePdfSource;

  /// PDF from raw bytes in memory.
  const factory PdfSource.memory(Uint8List bytes) = MemoryPdfSource;
}

class NetworkPdfSource extends PdfSource {
  const NetworkPdfSource(this.url, {this.headers = const {}});
  final String url;
  final Map<String, String> headers;
}

class AssetPdfSource extends PdfSource {
  const AssetPdfSource(this.assetPath);
  final String assetPath;
}

class FilePdfSource extends PdfSource {
  const FilePdfSource(this.filePath);
  final String filePath;
}

class MemoryPdfSource extends PdfSource {
  const MemoryPdfSource(this.bytes);
  final Uint8List bytes;
}

/// Source descriptor for images.
///
/// ## Usage:
/// ```dart
/// ImageSource.network('https://cdn.example.com/photo.jpg')
/// ImageSource.asset('assets/images/logo.png')
/// ImageSource.file('/storage/dcim/photo.jpg')
/// ImageSource.memory(decryptedPixels)
/// ```
sealed class ImageSource {
  const ImageSource();

  /// Image from a network URL.
  const factory ImageSource.network(
    String url, {
    Map<String, String> headers,
  }) = NetworkImageSource;

  /// Image bundled as a Flutter asset.
  const factory ImageSource.asset(String assetPath) = AssetImageSource;

  /// Image file on device storage.
  const factory ImageSource.file(String filePath) = FileImageSource;

  /// Image from raw bytes in memory.
  const factory ImageSource.memory(
    Uint8List bytes, {
    String mimeType,
  }) = MemoryImageSource;
}

class NetworkImageSource extends ImageSource {
  const NetworkImageSource(this.url, {this.headers = const {}});
  final String url;
  final Map<String, String> headers;
}

class AssetImageSource extends ImageSource {
  const AssetImageSource(this.assetPath);
  final String assetPath;
}

class FileImageSource extends ImageSource {
  const FileImageSource(this.filePath);
  final String filePath;
}

class MemoryImageSource extends ImageSource {
  const MemoryImageSource(this.bytes, {this.mimeType = 'image/png'});
  final Uint8List bytes;
  final String mimeType;
}
