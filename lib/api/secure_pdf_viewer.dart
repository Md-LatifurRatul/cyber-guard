import 'package:flutter/material.dart';

import '../ui/secure_content_widget.dart';
import '../viewers/pdf/pdf_controller.dart';
import '../viewers/pdf/pdf_page_renderer.dart';
import '../viewers/pdf/pdf_thumbnail_strip.dart';
import 'models/media_source.dart';
import 'models/player_config.dart';

/// Protected PDF document viewer with full CyberGuard security.
///
/// Renders PDF pages using platform-native APIs (PdfRenderer on Android,
/// PDFKit on iOS/macOS, Canvas rendering on web) with all security layers:
/// watermark, blur shield, screen capture prevention, and RASP monitoring.
///
/// ## Features:
/// - Page-by-page rendering at display resolution
/// - Pinch-to-zoom + double-tap zoom
/// - Swipe/scroll between pages
/// - Page number indicator + jump-to-page
/// - Thumbnail strip for quick navigation
/// - Text search within PDF
/// - Night mode (inverted colors)
/// - Network PDF download with progress
///
/// ## Usage:
/// ```dart
/// SecurePdfViewer(
///   source: PdfSource.network('https://example.com/report.pdf'),
///   config: const PdfViewerConfig(showThumbnails: true),
/// )
/// ```
class SecurePdfViewer extends StatefulWidget {
  const SecurePdfViewer({
    super.key,
    required this.source,
    this.config = const PdfViewerConfig(),
    this.onPageChanged,
    this.onError,
  });

  /// PDF document source (network URL, asset, file, or memory bytes).
  final PdfSource source;

  /// Viewer configuration (toolbar, thumbnails, zoom, etc.).
  final PdfViewerConfig config;

  /// Called when the user navigates to a different page.
  final void Function(int page)? onPageChanged;

  /// Called when a loading or rendering error occurs.
  final void Function(String error)? onError;

  @override
  State<SecurePdfViewer> createState() => _SecurePdfViewerState();
}

class _SecurePdfViewerState extends State<SecurePdfViewer> {
  late final PdfController _pdfController;
  late final PageController _pageController;
  bool _nightMode = false;
  bool _searchVisible = false;
  final _searchController = TextEditingController();
  List<PdfSearchResult> _searchResults = [];
  int _searchIndex = -1;

  String get _sourceLabel => switch (widget.source) {
        NetworkPdfSource(url: final url) =>
          Uri.tryParse(url)?.pathSegments.lastOrNull ?? 'PDF',
        AssetPdfSource(assetPath: final p) => p.split('/').last,
        FilePdfSource(filePath: final p) => p.split('/').last,
        MemoryPdfSource() => 'PDF Document',
      };

  @override
  void initState() {
    super.initState();
    _nightMode = widget.config.enableNightMode;
    _pageController = PageController(initialPage: widget.config.initialPage);

    _pdfController = PdfController(source: widget.source);
    _pdfController.pageCacheExtent = widget.config.pageCacheExtent;
    _pdfController.addListener(_onControllerChanged);
    _pdfController.open();
  }

  @override
  void dispose() {
    _pdfController.removeListener(_onControllerChanged);
    _pdfController.dispose();
    _pageController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  void _onControllerChanged() {
    if (mounted) setState(() {});
    if (_pdfController.errorMessage != null) {
      widget.onError?.call(_pdfController.errorMessage!);
    }
  }

  void _goToPage(int page) {
    if (page < 0 || page >= _pdfController.pageCount) return;
    _pdfController.goToPage(page);
    _pageController.animateToPage(
      page,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeInOut,
    );
    widget.onPageChanged?.call(page);
  }

  Future<void> _performSearch(String query) async {
    if (query.isEmpty) {
      setState(() {
        _searchResults = [];
        _searchIndex = -1;
      });
      return;
    }
    final results = await _pdfController.searchText(query);
    if (!mounted) return;
    setState(() {
      _searchResults = results;
      _searchIndex = results.isNotEmpty ? 0 : -1;
    });
    if (results.isNotEmpty) {
      _goToPage(results.first.pageIndex);
    }
  }

  void _nextSearchResult() {
    if (_searchResults.isEmpty) return;
    setState(() {
      _searchIndex = (_searchIndex + 1) % _searchResults.length;
    });
    _goToPage(_searchResults[_searchIndex].pageIndex);
  }

  void _previousSearchResult() {
    if (_searchResults.isEmpty) return;
    setState(() {
      _searchIndex =
          (_searchIndex - 1 + _searchResults.length) % _searchResults.length;
    });
    _goToPage(_searchResults[_searchIndex].pageIndex);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SecureContentWidget(
      child: ColorFiltered(
        colorFilter: _nightMode
            ? const ColorFilter.matrix(<double>[
                -1, 0, 0, 0, 255, //
                0, -1, 0, 0, 255, //
                0, 0, -1, 0, 255, //
                0, 0, 0, 1, 0, //
              ])
            : const ColorFilter.mode(Colors.transparent, BlendMode.dst),
        child: Column(
          children: [
            // Toolbar
            if (widget.config.showToolbar)
              _PdfToolbar(
                currentPage: _pdfController.currentPage,
                totalPages: _pdfController.pageCount,
                nightMode: _nightMode,
                enableSearch: widget.config.enableSearch,
                onNightModeToggled: () {
                  setState(() => _nightMode = !_nightMode);
                },
                onSearchToggled: () {
                  setState(() {
                    _searchVisible = !_searchVisible;
                    if (!_searchVisible) {
                      _searchController.clear();
                      _searchResults = [];
                      _searchIndex = -1;
                    }
                  });
                },
                sourceLabel: _sourceLabel,
              ),

            // Search bar
            if (_searchVisible)
              _PdfSearchBar(
                controller: _searchController,
                resultCount: _searchResults.length,
                currentIndex: _searchIndex,
                onSearch: _performSearch,
                onNext: _nextSearchResult,
                onPrevious: _previousSearchResult,
              ),

            // Page content
            Expanded(child: _buildContent(theme)),

            // Thumbnail strip
            if (widget.config.showThumbnails && _pdfController.isOpen)
              PdfThumbnailStrip(
                controller: _pdfController,
                currentPage: _pdfController.currentPage,
                onPageSelected: _goToPage,
              ),

            // Page indicator
            if (widget.config.showPageNumber && _pdfController.pageCount > 0)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  'Page ${_pdfController.currentPage + 1} of ${_pdfController.pageCount}',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildContent(ThemeData theme) {
    // Loading state
    if (_pdfController.isLoading) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 16),
            Text(
              'Loading $_sourceLabel...',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      );
    }

    // Error state
    if (_pdfController.errorMessage != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 48, color: Colors.red.shade300),
            const SizedBox(height: 16),
            Text(
              _pdfController.errorMessage!,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: Colors.red.shade400,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton.tonal(
              onPressed: () => _pdfController.open(),
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }

    // Empty document
    if (_pdfController.pageCount == 0) {
      return Center(
        child: Text(
          'No pages found',
          style: theme.textTheme.bodyMedium?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
      );
    }

    // Rendered pages
    return PageView.builder(
      controller: _pageController,
      scrollDirection: widget.config.scrollDirection == PdfScrollDirection.vertical
          ? Axis.vertical
          : Axis.horizontal,
      itemCount: _pdfController.pageCount,
      onPageChanged: (index) {
        _pdfController.goToPage(index);
        widget.onPageChanged?.call(index);
      },
      itemBuilder: (context, index) {
        final page = PdfPageRenderer(
          controller: _pdfController,
          pageIndex: index,
        );

        if (!widget.config.enableZoom) return page;

        return InteractiveViewer(
          minScale: 1.0,
          maxScale: widget.config.maxZoom,
          child: page,
        );
      },
    );
  }
}

/// PDF viewer toolbar with page navigation, search, and night mode toggle.
class _PdfToolbar extends StatelessWidget {
  const _PdfToolbar({
    required this.currentPage,
    required this.totalPages,
    required this.nightMode,
    required this.enableSearch,
    required this.onNightModeToggled,
    required this.onSearchToggled,
    required this.sourceLabel,
  });

  final int currentPage;
  final int totalPages;
  final bool nightMode;
  final bool enableSearch;
  final VoidCallback onNightModeToggled;
  final VoidCallback onSearchToggled;
  final String sourceLabel;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        border: Border(
          bottom: BorderSide(
            color: theme.colorScheme.outlineVariant,
          ),
        ),
      ),
      child: Row(
        children: [
          Icon(
            Icons.picture_as_pdf_rounded,
            size: 20,
            color: Colors.red.shade400,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              sourceLabel,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w500,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (enableSearch)
            IconButton(
              icon: const Icon(Icons.search, size: 20),
              onPressed: onSearchToggled,
              tooltip: 'Search',
              visualDensity: VisualDensity.compact,
            ),
          IconButton(
            icon: Icon(
              nightMode ? Icons.light_mode : Icons.dark_mode,
              size: 20,
            ),
            onPressed: onNightModeToggled,
            tooltip: nightMode ? 'Light mode' : 'Night mode',
            visualDensity: VisualDensity.compact,
          ),
        ],
      ),
    );
  }
}

/// Search bar for finding text within the PDF.
class _PdfSearchBar extends StatelessWidget {
  const _PdfSearchBar({
    required this.controller,
    required this.resultCount,
    required this.currentIndex,
    required this.onSearch,
    required this.onNext,
    required this.onPrevious,
  });

  final TextEditingController controller;
  final int resultCount;
  final int currentIndex;
  final ValueChanged<String> onSearch;
  final VoidCallback onNext;
  final VoidCallback onPrevious;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHigh,
        border: Border(
          bottom: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              decoration: InputDecoration(
                hintText: 'Search in PDF...',
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 8,
                ),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none,
                ),
                filled: true,
                fillColor: theme.colorScheme.surface,
                suffixText: resultCount > 0
                    ? '${currentIndex + 1}/$resultCount'
                    : null,
                suffixStyle: theme.textTheme.bodySmall,
              ),
              style: theme.textTheme.bodyMedium,
              textInputAction: TextInputAction.search,
              onSubmitted: onSearch,
            ),
          ),
          const SizedBox(width: 4),
          IconButton(
            icon: const Icon(Icons.keyboard_arrow_up, size: 20),
            onPressed: resultCount > 0 ? onPrevious : null,
            visualDensity: VisualDensity.compact,
            tooltip: 'Previous result',
          ),
          IconButton(
            icon: const Icon(Icons.keyboard_arrow_down, size: 20),
            onPressed: resultCount > 0 ? onNext : null,
            visualDensity: VisualDensity.compact,
            tooltip: 'Next result',
          ),
        ],
      ),
    );
  }
}
