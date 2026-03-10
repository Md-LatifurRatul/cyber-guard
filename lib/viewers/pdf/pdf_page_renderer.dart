import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import 'pdf_controller.dart';

/// Renders a single PDF page from native RGBA pixel data.
///
/// Uses [PdfController.renderPage] to get pixel data, then
/// decodes it into a [ui.Image] for display via [RawImage].
///
/// The page is rendered at the widget's actual pixel dimensions
/// (accounting for device pixel ratio) for crisp output.
class PdfPageRenderer extends StatefulWidget {
  const PdfPageRenderer({
    super.key,
    required this.controller,
    required this.pageIndex,
    this.backgroundColor = Colors.white,
  });

  final PdfController controller;
  final int pageIndex;
  final Color backgroundColor;

  @override
  State<PdfPageRenderer> createState() => _PdfPageRendererState();
}

class _PdfPageRendererState extends State<PdfPageRenderer> {
  ui.Image? _image;
  bool _isRendering = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _render();
  }

  @override
  void didUpdateWidget(PdfPageRenderer oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.pageIndex != widget.pageIndex) {
      _render();
    }
  }

  @override
  void dispose() {
    _image?.dispose();
    super.dispose();
  }

  Future<void> _render() async {
    if (_isRendering) return;
    setState(() {
      _isRendering = true;
      _error = null;
    });

    try {
      // Get page size to calculate aspect ratio
      final pageSize = await widget.controller.getPageSize(widget.pageIndex);
      if (!mounted) return;

      final dpr = MediaQuery.of(context).devicePixelRatio;
      final availableWidth = MediaQuery.of(context).size.width;

      // Render at display resolution
      final renderWidth = (availableWidth * dpr).toInt().clamp(100, 4096);
      final aspectRatio = pageSize?.aspectRatio ?? (612 / 792);
      final renderHeight = (renderWidth / aspectRatio).toInt().clamp(100, 4096);

      final rendered = await widget.controller.renderPage(
        widget.pageIndex,
        width: renderWidth,
        height: renderHeight,
      );

      if (!mounted) return;

      if (rendered == null) {
        setState(() {
          _isRendering = false;
          _error = 'Failed to render page ${widget.pageIndex + 1}';
        });
        return;
      }

      // Decode RGBA pixels into a ui.Image
      final completer = _ImageCompleter();
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

      // Dispose previous image
      _image?.dispose();

      setState(() {
        _image = image;
        _isRendering = false;
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _isRendering = false;
          _error = 'Render error: $e';
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return Container(
        color: widget.backgroundColor,
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.error_outline, size: 32, color: Colors.red.shade300),
              const SizedBox(height: 8),
              Text(
                _error!,
                style: TextStyle(color: Colors.red.shade400, fontSize: 12),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }

    if (_isRendering || _image == null) {
      return Container(
        color: widget.backgroundColor,
        child: const Center(
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }

    return Container(
      color: widget.backgroundColor,
      child: Center(
        child: RawImage(
          image: _image,
          fit: BoxFit.contain,
        ),
      ),
    );
  }
}

/// Helper to bridge callback-style image decoding to Future.
class _ImageCompleter {
  final _completer = Completer<ui.Image>();

  Future<ui.Image> get future => _completer.future;

  void complete(ui.Image image) {
    _completer.complete(image);
  }
}
