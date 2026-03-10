import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../../platform/web_security_bridge.dart';
import 'security_config.dart';
import 'security_event.dart';
import 'security_state.dart';

/// The central bridge between Flutter and native platform security code.
///
/// This is a singleton — there must be exactly ONE channel to native code.
/// Multiple instances would cause duplicate event handling and conflicting
/// state.
///
/// ## Usage
/// ```dart
/// final channel = SecurityChannel.instance;
/// await channel.initialize(config);
/// channel.stateStream.listen((state) {
///   if (state.shouldBlurContent) { /* blur */ }
/// });
/// ```
///
/// ## Architecture
/// ```
/// Dart (SecurityChannel)
///   ├── MethodChannel → sends commands to native
///   │   "enterSecureMode", "exitSecureMode", "getDeviceIntegrity"
///   └── EventChannel ← receives events from native
///       SecurityEvent stream (capture, debug, root, hook...)
/// ```
class SecurityChannel {
  SecurityChannel._();

  static final SecurityChannel instance = SecurityChannel._();

  // ─── Channel Names (must match native side exactly) ───

  static const String _methodChannelName = 'com.cyberguard.security/bridge';
  static const String _eventChannelName = 'com.cyberguard.security/events';

  // ─── Platform Channels ───

  final MethodChannel _methodChannel =
      const MethodChannel(_methodChannelName);
  final EventChannel _eventChannel =
      const EventChannel(_eventChannelName);

  // ─── Web Bridge (only active on web platform) ───

  /// On web, MethodChannel doesn't reach native code — there IS no native.
  /// Instead, we use WebSecurityBridge to call security_guard.js directly.
  /// On native platforms, this is a no-op stub.
  late final WebSecurityBridge _webBridge = createWebSecurityBridge();

  // ─── State Management ───

  final StreamController<SecurityState> _stateController =
      StreamController<SecurityState>.broadcast();
  final StreamController<SecurityEvent> _eventController =
      StreamController<SecurityEvent>.broadcast();

  SecurityState _currentState = const SecurityState();
  SecurityConfig _config = const SecurityConfig();
  bool _initialized = false;
  StreamSubscription<dynamic>? _eventSubscription;

  /// Stream of security state changes. Listen to this for UI updates.
  Stream<SecurityState> get stateStream => _stateController.stream;

  /// Stream of raw security events. Listen to this for logging/forensics.
  Stream<SecurityEvent> get eventStream => _eventController.stream;

  /// Current security state snapshot.
  SecurityState get currentState => _currentState;

  /// Current configuration.
  SecurityConfig get config => _config;

  /// Whether the channel has been initialized.
  bool get isInitialized => _initialized;

  /// Initialize the security channel with the given configuration.
  ///
  /// This MUST be called before [enterSecureMode] or any other method.
  /// Typically called in `main()` before `runApp()`.
  ///
  /// 1. Sets up the MethodChannel handler for native → Dart calls
  /// 2. Subscribes to EventChannel for continuous security events
  /// 3. Sends config to native side for platform-specific initialization
  Future<void> initialize(SecurityConfig config) async {
    if (_initialized) return;

    _config = config;

    // Handle method calls FROM native (native calling Dart)
    _methodChannel.setMethodCallHandler(_handleNativeMethodCall);

    // Subscribe to security event stream FROM native
    _eventSubscription = _eventChannel
        .receiveBroadcastStream()
        .listen(
          _handleNativeEvent,
          onError: _handleEventError,
          cancelOnError: false,
        );

    // Send configuration TO native side (or web bridge)
    if (kIsWeb) {
      // Web: Initialize the JS security engine directly.
      // MethodChannel doesn't reach native code on web — there is no native.
      _webBridge.initialize(config.toMap());
      _webBridge.setEventCallback(_handleWebEvent);
    } else {
      // Native: Use MethodChannel to reach Android/iOS/macOS plugin.
      try {
        await _methodChannel.invokeMethod<void>(
          'initialize',
          config.toMap(),
        );
      } on MissingPluginException {
        // Platform plugin not registered yet (e.g., running on unsupported platform).
        // Security features will be unavailable but app won't crash.
        debugPrint('CyberGuard: Native plugin not available on this platform.');
      }
    }

    _initialized = true;
  }

  /// Enter secure mode — activates all protection flags.
  ///
  /// On Android: Sets FLAG_SECURE, starts native monitoring thread.
  /// On iOS: Sets UIScreen observation, starts Metal secure rendering.
  /// On macOS: Sets NSWindow.sharingType = .none.
  /// On Web: Activates canvas protection, DevTools detection, shortcuts.
  Future<void> enterSecureMode() async {
    _assertInitialized();
    if (kIsWeb) {
      _webBridge.activate();
      _updateState(_currentState.withSecureMode(active: true));
    } else {
      try {
        await _methodChannel.invokeMethod<void>('enterSecureMode');
        _updateState(_currentState.withSecureMode(active: true));
      } on MissingPluginException {
        debugPrint('CyberGuard: enterSecureMode not available.');
      }
    }
  }

  /// Exit secure mode — deactivates protection flags.
  ///
  /// Call this when the user navigates away from secure content.
  /// Keeps monitoring active but removes display-level protections.
  Future<void> exitSecureMode() async {
    _assertInitialized();
    if (kIsWeb) {
      _webBridge.deactivate();
      _updateState(_currentState.withSecureMode(active: false));
    } else {
      try {
        await _methodChannel.invokeMethod<void>('exitSecureMode');
        _updateState(_currentState.withSecureMode(active: false));
      } on MissingPluginException {
        debugPrint('CyberGuard: exitSecureMode not available.');
      }
    }
  }

  /// Query the device integrity status.
  ///
  /// Returns a map with keys: 'isRooted', 'isEmulator', 'isHooked',
  /// 'isDebugger', 'isIntegrityValid'.
  ///
  /// On web: returns DevTools open status. Root/emulator/hook don't
  /// apply to web — browsers don't have those concepts.
  Future<Map<String, bool>> getDeviceIntegrity() async {
    _assertInitialized();
    if (kIsWeb) {
      final status = _webBridge.getStatus();
      return {
        'isRooted': false,
        'isEmulator': false,
        'isHooked': false,
        'isDebugger': status['isDevToolsOpen'] ?? false,
        'isIntegrityValid': true,
      };
    }
    try {
      final result = await _methodChannel
          .invokeMapMethod<String, bool>('getDeviceIntegrity');
      return result ?? {};
    } on MissingPluginException {
      debugPrint('CyberGuard: getDeviceIntegrity not available.');
      return {};
    }
  }

  /// Notify native side that the app is being backgrounded.
  ///
  /// Native code should immediately clear secure surfaces and
  /// prepare for task switcher screenshot protection.
  Future<void> notifyAppBackgrounded() async {
    if (!_initialized) return;
    try {
      await _methodChannel.invokeMethod<void>('appBackgrounded');
    } on MissingPluginException {
      // Silently ignore — non-critical.
    }
  }

  /// Notify native side that the app has returned to foreground.
  Future<void> notifyAppForegrounded() async {
    if (!_initialized) return;
    try {
      await _methodChannel.invokeMethod<void>('appForegrounded');
    } on MissingPluginException {
      // Silently ignore — non-critical.
    }
  }

  /// Clean up resources. Call when the app is being destroyed.
  Future<void> dispose() async {
    _webBridge.dispose();
    await _eventSubscription?.cancel();
    _eventSubscription = null;
    await _stateController.close();
    await _eventController.close();
    _initialized = false;
  }

  // ─── Private Handlers ───

  /// Handle method calls initiated by native code.
  ///
  /// Native side can call Dart for:
  /// - 'onSecurityBreach': immediate threat notification
  /// - 'onCaptureCleared': screen capture has stopped
  Future<dynamic> _handleNativeMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onSecurityBreach':
        final args = call.arguments;
        if (args is Map) {
          final event = SecurityEvent.fromPlatformMap(
            Map<Object?, Object?>.from(args),
          );
          _processEvent(event);
        }
      case 'onCaptureCleared':
        _updateState(_currentState.clearScreenCapture());
    }
  }

  /// Handle events from the native EventChannel stream.
  void _handleNativeEvent(dynamic rawEvent) {
    if (rawEvent is Map) {
      final event = SecurityEvent.fromPlatformMap(
        Map<Object?, Object?>.from(rawEvent),
      );
      _processEvent(event);
    }
  }

  /// Handle security events from the web JavaScript bridge.
  ///
  /// Events arrive as Maps from security_guard.js via dart:js_interop.
  /// They follow the same schema as native events:
  /// `{type: string, severity: string, timestamp: int, metadata: {}}`
  void _handleWebEvent(Map<String, dynamic> eventMap) {
    final event = SecurityEvent.fromPlatformMap(
      eventMap.map((k, v) => MapEntry(k as Object, v as Object?)),
    );
    _processEvent(event);
  }

  /// Handle errors from the EventChannel stream.
  void _handleEventError(Object error) {
    debugPrint('CyberGuard: Event stream error: $error');
  }

  /// Process a security event: update state and notify listeners.
  void _processEvent(SecurityEvent event) {
    // Emit raw event for logging/forensics
    if (!_eventController.isClosed) {
      _eventController.add(event);
    }

    // Update state
    _updateState(_currentState.applyEvent(event));

    // Handle critical events
    if (event.requiresTermination && _config.terminateOnCritical) {
      _emergencyShutdown();
    }
  }

  /// Update state and notify listeners.
  void _updateState(SecurityState newState) {
    _currentState = newState;
    if (!_stateController.isClosed) {
      _stateController.add(newState);
    }
  }

  /// Emergency shutdown — native process kill.
  Future<void> _emergencyShutdown() async {
    try {
      await _methodChannel.invokeMethod<void>('emergencyShutdown');
    } on MissingPluginException {
      // Can't kill natively — at least clear the UI.
    }
  }

  void _assertInitialized() {
    assert(
      _initialized,
      'SecurityChannel.initialize() must be called before using any methods.',
    );
  }
}
