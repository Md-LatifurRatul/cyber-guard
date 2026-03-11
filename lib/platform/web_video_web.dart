import 'dart:js_interop';
import 'dart:ui_web' as ui_web;

import 'package:flutter/material.dart';

// ─── JS Interop bindings for DOM manipulation ───

@JS('document.createElement')
external JSObject _createElement(JSString tagName);

/// Extension type for HTMLVideoElement properties.
extension type _JSVideoElement(JSObject _) implements JSObject {
  external set src(JSString value);
  external set controls(JSBoolean value);
  external set autoplay(JSBoolean value);
  external set volume(JSNumber value);
  external void setAttribute(JSString name, JSString value);
  external void addEventListener(JSString type, JSFunction listener);
  external _JSStyle get style;
}

/// Extension type for CSSStyleDeclaration.
extension type _JSStyle(JSObject _) implements JSObject {
  external set width(JSString value);
  external set height(JSString value);
  external set objectFit(JSString value);
  external set backgroundColor(JSString value);
  external set userSelect(JSString value);
  external void setProperty(JSString property, JSString value);
}

/// Extension type for Event.preventDefault().
extension type _JSEvent(JSObject _) implements JSObject {
  external void preventDefault();
}

/// Web implementation: creates an HTML5 <video> element and registers
/// it as a platform view for HtmlElementView.
Widget createWebVideoElement({
  required String url,
  required String elementId,
  required bool autoPlay,
  required double volume,
}) {
  // Register the platform view factory
  ui_web.platformViewRegistry.registerViewFactory(
    elementId,
    (int viewId, {Object? params}) {
      final video = _createElement('video'.toJS) as _JSVideoElement;

      // Source
      video.src = url.toJS;

      // Sizing
      video.style.width = '100%'.toJS;
      video.style.height = '100%'.toJS;
      video.style.objectFit = 'contain'.toJS;
      video.style.backgroundColor = '#000'.toJS;

      // Attributes
      video.setAttribute('playsinline'.toJS, ''.toJS);
      video.setAttribute('webkit-playsinline'.toJS, ''.toJS);

      // Security: disable download controls
      video.setAttribute('controlsList'.toJS, 'nodownload noremoteplayback'.toJS);
      video.setAttribute('disablePictureInPicture'.toJS, ''.toJS);
      video.controls = true.toJS;
      video.volume = volume.toJS;
      video.autoplay = autoPlay.toJS;

      // CSS security
      video.style.userSelect = 'none'.toJS;
      video.style.setProperty('-webkit-user-select'.toJS, 'none'.toJS);

      // Prevent context menu (right-click → Save Video As)
      video.addEventListener(
        'contextmenu'.toJS,
        ((_JSEvent e) {
          e.preventDefault();
        }).toJS,
      );

      // Prevent drag (drag to desktop)
      video.addEventListener(
        'dragstart'.toJS,
        ((_JSEvent e) {
          e.preventDefault();
        }).toJS,
      );

      return video as JSObject;
    },
  );

  return HtmlElementView(viewType: elementId);
}
