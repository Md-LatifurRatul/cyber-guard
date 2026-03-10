import 'dart:js_interop';

import 'web_security_bridge.dart';

/// Real web implementation using dart:js_interop.
///
/// ## How dart:js_interop works:
///
/// `dart:js_interop` is Dart's modern way to call JavaScript from Dart.
/// It replaces the deprecated `dart:js` and `dart:html`.
///
/// Key concepts:
/// - `@JS()` annotation binds a Dart declaration to a JavaScript name
/// - `external` means "this function exists in JavaScript, not Dart"
/// - `.toJS` converts Dart values to JS values
/// - `.toDart` converts JS values back to Dart
///
/// ## Why not dart:html:
/// `dart:html` is deprecated as of Dart 3.3. `dart:js_interop` is the
/// replacement and works with both dart2js and dart2wasm compilers.
WebSecurityBridge createPlatformBridge() => _WebSecurityBridgeWeb();

// ─── JS Interop Bindings ───
// These declarations map Dart calls to the global CyberGuardSecurity object
// defined in web/security_guard.js.

@JS('CyberGuardSecurity.initialize')
external void _jsInitialize(JSObject config);

@JS('CyberGuardSecurity.activate')
external void _jsActivate();

@JS('CyberGuardSecurity.deactivate')
external void _jsDeactivate();

@JS('CyberGuardSecurity.getStatus')
external _JSStatusResult _jsGetStatus();

@JS('CyberGuardSecurity.destroy')
external void _jsDestroy();

@JS('CyberGuardSecurity')
external JSObject get _jsCyberGuard;

/// Extension type for the CyberGuardSecurity global object.
/// Allows setting the onSecurityEvent property.
extension type _JSCyberGuard(JSObject _) implements JSObject {
  external set onSecurityEvent(JSFunction? value);
}

/// Extension type for reading status result properties.
extension type _JSStatusResult(JSObject _) implements JSObject {
  external JSBoolean get isDevToolsOpen;
  external JSBoolean get isActive;
  external JSBoolean get isInitialized;
}

/// Extension type for reading event properties from JS.
extension type _JSSecurityEvent(JSObject _) implements JSObject {
  external JSString? get type;
  external JSString? get severity;
  external JSNumber? get timestamp;
}

/// JS helper to create a plain object ({}).
@JS('Object.create')
external JSObject _jsObjectCreate(JSAny? proto);

/// JS helper to set a property on an object: obj[key] = value.
@JS('Reflect.set')
external void _jsReflectSet(JSObject target, JSString key, JSAny? value);

class _WebSecurityBridgeWeb implements WebSecurityBridge {
  void Function(Map<String, dynamic> event)? _dartCallback;

  @override
  void initialize(Map<String, dynamic> config) {
    final jsConfig = _dartMapToJSObject(config);
    _jsInitialize(jsConfig);
  }

  @override
  void activate() {
    _jsActivate();
  }

  @override
  void deactivate() {
    _jsDeactivate();
  }

  @override
  Map<String, bool> getStatus() {
    final jsStatus = _jsGetStatus();
    return {
      'isDevToolsOpen': jsStatus.isDevToolsOpen.toDart,
      'isActive': jsStatus.isActive.toDart,
      'isInitialized': jsStatus.isInitialized.toDart,
    };
  }

  @override
  void setEventCallback(
      void Function(Map<String, dynamic> event)? callback) {
    _dartCallback = callback;

    if (callback != null) {
      // Create a JS function that converts the JS event and calls Dart
      final jsCallback = ((JSObject jsEvent) {
        final dartEvent = _jsEventToDartMap(jsEvent);
        _dartCallback?.call(dartEvent);
      }).toJS;

      // Set CyberGuardSecurity.onSecurityEvent = jsCallback
      (_jsCyberGuard as _JSCyberGuard).onSecurityEvent = jsCallback;
    } else {
      (_jsCyberGuard as _JSCyberGuard).onSecurityEvent = null;
    }
  }

  @override
  void dispose() {
    _dartCallback = null;
    _jsDestroy();
  }

  // ─── Conversion helpers ───

  /// Convert a Dart map to a plain JS object using Reflect.set.
  JSObject _dartMapToJSObject(Map<String, dynamic> map) {
    final obj = _jsObjectCreate(null);
    for (final entry in map.entries) {
      final key = entry.key.toJS;
      final value = entry.value;
      if (value is bool) {
        _jsReflectSet(obj, key, value.toJS);
      } else if (value is int) {
        _jsReflectSet(obj, key, value.toJS);
      } else if (value is String) {
        _jsReflectSet(obj, key, value.toJS);
      }
    }
    return obj;
  }

  /// Convert a JS security event to a Dart map.
  Map<String, dynamic> _jsEventToDartMap(JSObject obj) {
    final event = obj as _JSSecurityEvent;
    final map = <String, dynamic>{};

    final type = event.type;
    if (type != null) map['type'] = type.toDart;

    final severity = event.severity;
    if (severity != null) map['severity'] = severity.toDart;

    final timestamp = event.timestamp;
    if (timestamp != null) map['timestamp'] = timestamp.toDartInt;

    map['metadata'] = <String, dynamic>{};

    return map;
  }
}
