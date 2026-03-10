import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import 'pdf_controller.dart';

/// Horizontal thumbnail strip for quick PDF page navigation.
///
/// Renders small previews of each page and highlights the current page.
/// Tapping a thumbnail navigates to that page via [PdfController.goToPage].
///
/// Thumbnails are rendered lazily as they scroll into view and cached
/// to avoid redundant native rendering calls.
class PdfThumbnailStrip extends StatefulWidget {
  const PdfThumbnailStrip({
    super.key,
    required this.controller,
    required this.currentPage,
    required this.onPageSelected,
    this.height = 80,
    this.thumbnailWidth = 56,
    this.selectedBorderColor,
  });

  final PdfController controller;
  final int currentPage;
  final ValueChanged<int> onPageSelected;
  final double height;
  final double thumbnailWidth;
  final Color? selectedBorderColor;

  @override
  State<PdfThumbnailStrip> createState() => _PdfThumbnailStripState();
}

class _PdfThumbnailStripState extends State<PdfThumbnailStrip> {
  late final ScrollController _scrollController;

  @override
  void initState() {
    super.initState();
    _scrollController = ScrollController();
    WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToPage());
  }

  @override
  void didUpdateWidget(PdfThumbnailStrip oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.currentPage != widget.currentPage) {
      _scrollToPage();
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToPage() {
    if (!_scrollController.hasClients) return;
    final itemWidth = widget.thumbnailWidth + 8; // width + margin
    final targetOffset =
        (widget.currentPage * itemWidth) - (_scrollController.position.viewportDimension / 2) + (itemWidth / 2);
    _scrollController.animateTo(
      targetOffset.clamp(0.0, _scrollController.position.maxScrollExtent),
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeInOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accentColor = widget.selectedBorderColor ?? theme.colorScheme.primary;

    return Container(
      height: widget.height,
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        border: Border(
          top: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
      ),
      child: ListView.builder(
        controller: _scrollController,
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        itemCount: widget.controller.pageCount,
        itemBuilder: (context, index) {
          final isSelected = index == widget.currentPage;
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4),
            child: GestureDetector(
              onTap: () => widget.onPageSelected(index),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                width: widget.thumbnailWidth,
                decoration: BoxDecoration(
                  border: Border.all(
                    color: isSelected ? accentColor : Colors.transparent,
                    width: 2,
                  ),
                  borderRadius: BorderRadius.circular(4),
                  boxShadow: isSelected
                      ? [
                          BoxShadow(
                            color: accentColor.withValues(alpha: 0.3),
                            blurRadius: 6,
                          ),
                        ]
                      : null,
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(2),
                  child: _ThumbnailTile(
                    controller: widget.controller,
                    pageIndex: index,
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

/// Renders a single thumbnail by fetching a low-res render from native.
class _ThumbnailTile extends StatefulWidget {
  const _ThumbnailTile({
    required this.controller,
    required this.pageIndex,
  });

  final PdfController controller;
  final int pageIndex;

  @override
  State<_ThumbnailTile> createState() => _ThumbnailTileState();
}

class _ThumbnailTileState extends State<_ThumbnailTile> {
  ui.Image? _image;
  bool _isRendering = false;

  @override
  void initState() {
    super.initState();
    _render();
  }

  @override
  void dispose() {
    _image?.dispose();
    super.dispose();
  }

  Future<void> _render() async {
    if (_isRendering) return;
    _isRendering = true;

    try {
      // Render at small resolution for thumbnails
      const thumbWidth = 120;
      final pageSize = await widget.controller.getPageSize(widget.pageIndex);
      final aspectRatio = pageSize?.aspectRatio ?? (612 / 792);
      final thumbHeight = (thumbWidth / aspectRatio).toInt().clamp(100, 300);

      final rendered = await widget.controller.renderPage(
        widget.pageIndex,
        width: thumbWidth,
        height: thumbHeight,
      );

      if (!mounted) return;

      if (rendered == null) {
        _isRendering = false;
        return;
      }

      final completer = Completer<ui.Image>();
      ui.decodeImageFromPixels(
        rendered.pixels,
        rendered.width,
        rendered.height,
        ui.PixelFormat.rgba8888,
        completer.complete,
      );

      final image = await completer.future;
      if (!mounted) {
        image.dispose();
        return;
      }

      _image?.dispose();
      setState(() {
        _image = image;
        _isRendering = false;
      });
    } catch (_) {
      if (mounted) {
        setState(() => _isRendering = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_image != null) {
      return RawImage(
        image: _image,
        fit: BoxFit.cover,
      );
    }

    return Container(
      color: Colors.grey.shade200,
      child: Center(
        child: Text(
          '${widget.pageIndex + 1}',
          style: TextStyle(
            color: Colors.grey.shade500,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }
}
