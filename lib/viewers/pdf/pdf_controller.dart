import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../api/models/media_source.dart';

/// Controller for native PDF rendering via MethodChannel.
///
/// Manages the lifecycle of a PDF document:
/// open → renderPage → searchText → close.
///
/// Each [PdfController] owns one native document handle. Pages are
/// rendered as RGBA pixel data and displayed via [RawImage] in Dart.
///
/// On web, delegates to the JavaScript CyberGuardPdf bridge. Since the
/// browser cannot render PDF pages to pixels without PDF.js, the web
/// implementation stores the document URL for iframe-based viewing.
///
/// ## Usage:
/// ```dart
/// final controller = PdfController(source: PdfSource.network(url));
/// await controller.open();
/// final page = await controller.renderPage(0, width: 800, height: 1200);
/// // ... display page.pixels via RawImage ...
/// await controller.close();
/// ```
class PdfController extends ChangeNotifier {
  PdfController({required this.source});

  static const _channel = MethodChannel('com.cyberguard.security/pdf');

  /// PDF document source.
  final PdfSource source;

  /// Native document ID assigned by the platform.
  String? _documentId;

  /// Total number of pages in the document.
  int _pageCount = 0;
  int get pageCount => _pageCount;

  /// Current page index (0-based).
  int _currentPage = 0;
  int get currentPage => _currentPage;

  /// Whether the document is currently loading.
  bool _isLoading = false;
  bool get isLoading => _isLoading;

  /// Whether the document has been opened successfully.
  bool get isOpen => _documentId != null;

  /// Error message if opening or rendering failed.
  String? _errorMessage;
  String? get errorMessage => _errorMessage;

  /// The document URL for web iframe rendering.
  String? _webUrl;
  String? get webUrl => _webUrl;

  /// Cache of rendered page pixels (pageIndex → RenderedPage).
  final Map<int, RenderedPage> _pageCache = {};

  /// Number of pages to pre-render around the current page.
  int pageCacheExtent = 2;

  bool _disposed = false;

  // ─── Lifecycle ───

  /// Open the PDF document and get page count.
  Future<void> open() async {
    if (_disposed || isOpen) return;
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    if (kIsWeb) {
      await _openWeb();
      return;
    }

    try {
      final sourceData = _encodeSource(source);
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'open',
        {'source': sourceData},
      );

      if (result == null) {
        _errorMessage = 'Native PDF renderer returned null';
        _isLoading = false;
        notifyListeners();
        return;
      }

      _documentId = result['documentId'] as String?;
      _pageCount = (result['pageCount'] as int?) ?? 0;
      _isLoading = false;
      notifyListeners();
    } on PlatformException catch (e) {
      _errorMessage = e.message ?? 'Failed to open PDF: ${e.code}';
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Web-specific open using URL resolution.
  Future<void> _openWeb() async {
    try {
      // Resolve the source to a URL
      _webUrl = switch (source) {
        NetworkPdfSource(url: final url) => url,
        AssetPdfSource(assetPath: final path) => 'assets/$path',
        FilePdfSource(filePath: final path) => path,
        MemoryPdfSource() => null,
      };

      _documentId = 'web_pdf_${DateTime.now().millisecondsSinceEpoch}';
      _pageCount = 1; // Web can't detect page count without PDF.js
      _isLoading = false;
      notifyListeners();
    } catch (e) {
      _errorMessage = 'Failed to open PDF on web: $e';
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Render a specific page at the given dimensions.
  ///
  /// Returns [RenderedPage] with RGBA pixel data, or null on error.
  /// Results are cached — subsequent calls for the same page return
  /// the cached version.
  ///
  /// On web, returns null (web uses iframe-based rendering instead).
  Future<RenderedPage?> renderPage(
    int pageIndex, {
    required int width,
    required int height,
  }) async {
    if (_disposed || _documentId == null) return null;
    if (pageIndex < 0 || pageIndex >= _pageCount) return null;

    // Web cannot render to pixels without PDF.js
    if (kIsWeb) return null;

    // Check cache
    final cached = _pageCache[pageIndex];
    if (cached != null && cached.width == width && cached.height == height) {
      return cached;
    }

    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'renderPage',
        {
          'documentId': _documentId,
          'pageIndex': pageIndex,
          'width': width,
          'height': height,
        },
      );

      if (result == null) return null;

      final pixels = result['pixels'] as Uint8List?;
      final pageWidth = (result['width'] as int?) ?? width;
      final pageHeight = (result['height'] as int?) ?? height;

      if (pixels == null) return null;

      final rendered = RenderedPage(
        pageIndex: pageIndex,
        pixels: pixels,
        width: pageWidth,
        height: pageHeight,
      );

      // Cache the result
      _pageCache[pageIndex] = rendered;

      // Evict old cache entries if too many
      _evictCache(pageIndex);

      return rendered;
    } on PlatformException catch (e) {
      debugPrint('CyberGuard: PDF render error: ${e.message}');
      return null;
    }
  }

  /// Get the native size of a page (in points).
  Future<PageSize?> getPageSize(int pageIndex) async {
    if (_disposed || _documentId == null) return null;

    // Web: return default US Letter size
    if (kIsWeb) return const PageSize(width: 612, height: 792);

    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'getPageSize',
        {
          'documentId': _documentId,
          'pageIndex': pageIndex,
        },
      );

      if (result == null) return null;

      return PageSize(
        width: (result['width'] as num?)?.toDouble() ?? 612,
        height: (result['height'] as num?)?.toDouble() ?? 792,
      );
    } on PlatformException {
      return null;
    }
  }

  /// Search for text within the document.
  ///
  /// Returns a list of search results with page index and match rects.
  /// Not available on web without PDF.js.
  Future<List<PdfSearchResult>> searchText(String query) async {
    if (_disposed || _documentId == null || query.isEmpty) return [];

    // Web: text search not available
    if (kIsWeb) return [];

    try {
      final result = await _channel.invokeListMethod<Map<dynamic, dynamic>>(
        'searchText',
        {
          'documentId': _documentId,
          'query': query,
        },
      );

      if (result == null) return [];

      return result.map((match) {
        return PdfSearchResult(
          pageIndex: (match['page'] as int?) ?? 0,
          matchText: (match['text'] as String?) ?? query,
        );
      }).toList();
    } on PlatformException {
      return [];
    }
  }

  /// Navigate to a specific page.
  void goToPage(int pageIndex) {
    if (pageIndex < 0 || pageIndex >= _pageCount) return;
    _currentPage = pageIndex;
    notifyListeners();
  }

  /// Go to the next page.
  void nextPage() {
    if (_currentPage < _pageCount - 1) {
      _currentPage++;
      notifyListeners();
    }
  }

  /// Go to the previous page.
  void previousPage() {
    if (_currentPage > 0) {
      _currentPage--;
      notifyListeners();
    }
  }

  // ─── Cache Management ───

  void _evictCache(int currentPage) {
    if (_pageCache.length <= (pageCacheExtent * 2 + 1)) return;

    final keysToRemove = _pageCache.keys
        .where((k) => (k - currentPage).abs() > pageCacheExtent)
        .toList();

    for (final key in keysToRemove) {
      _pageCache.remove(key);
    }
  }

  /// Clear the entire page cache.
  void clearCache() {
    _pageCache.clear();
  }

  // ─── Source Encoding ───

  Map<String, dynamic> _encodeSource(PdfSource source) {
    return switch (source) {
      NetworkPdfSource(url: final url, headers: final headers) => {
          'type': 'network',
          'url': url,
          'headers': headers,
        },
      AssetPdfSource(assetPath: final path) => {
          'type': 'asset',
          'assetPath': path,
        },
      FilePdfSource(filePath: final path) => {
          'type': 'file',
          'filePath': path,
        },
      MemoryPdfSource(bytes: final bytes) => {
          'type': 'memory',
          'bytes': bytes,
        },
    };
  }

  // ─── Disposal ───

  /// Close the native PDF document and release resources.
  Future<void> close() async {
    if (_documentId != null && !kIsWeb) {
      try {
        await _channel.invokeMethod('close', {'documentId': _documentId});
      } on PlatformException {
        // Best-effort cleanup
      }
    }
    _documentId = null;
    _webUrl = null;
    _pageCache.clear();
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await close();
    super.dispose();
  }
}

/// A rendered PDF page as RGBA pixel data.
class RenderedPage {
  const RenderedPage({
    required this.pageIndex,
    required this.pixels,
    required this.width,
    required this.height,
  });

  final int pageIndex;
  final Uint8List pixels;
  final int width;
  final int height;
}

/// Native page size in points.
class PageSize {
  const PageSize({required this.width, required this.height});

  final double width;
  final double height;

  double get aspectRatio => width / height;
}

/// A text search result within the PDF.
class PdfSearchResult {
  const PdfSearchResult({
    required this.pageIndex,
    required this.matchText,
  });

  final int pageIndex;
  final String matchText;
}
