import 'dart:js_interop';
import 'dart:ui_web' as ui_web;

import 'package:flutter/material.dart';

// ─── JS Interop bindings for DOM manipulation ───

@JS('document.createElement')
external JSObject _createElement(JSString tagName);

/// Extension type for HTMLIFrameElement properties.
extension type _JSIFrameElement(JSObject _) implements JSObject {
  external set src(JSString value);
  external void setAttribute(JSString name, JSString value);
  external _JSStyle get style;
}

/// Extension type for CSSStyleDeclaration.
extension type _JSStyle(JSObject _) implements JSObject {
  external set width(JSString value);
  external set height(JSString value);
  external set border(JSString value);
  external set backgroundColor(JSString value);
}

/// Web implementation: creates an <iframe> to display a PDF
/// using the browser's built-in PDF viewer.
Widget createWebPdfView({
  required String url,
  required String elementId,
}) {
  ui_web.platformViewRegistry.registerViewFactory(
    elementId,
    (int viewId, {Object? params}) {
      final iframe = _createElement('iframe'.toJS) as _JSIFrameElement;

      iframe.src = url.toJS;
      iframe.style.width = '100%'.toJS;
      iframe.style.height = '100%'.toJS;
      iframe.style.border = 'none'.toJS;
      iframe.style.backgroundColor = '#1a1a2e'.toJS;
      iframe.setAttribute('sandbox'.toJS, 'allow-same-origin allow-scripts'.toJS);

      return iframe as JSObject;
    },
  );

  return HtmlElementView(viewType: elementId);
}
