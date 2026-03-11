import 'security_event.dart';

/// Runtime security state of the application.
///
/// Tracks the current threat landscape: which threats are active,
/// whether the device is compromised, and the overall protection status.
/// Updated in real-time as [SecurityEvent]s arrive from native code.
class SecurityState {
  const SecurityState({
    this.isSecureModeActive = false,
    this.isScreenBeingCaptured = false,
    this.isDebuggerAttached = false,
    this.isDeviceRooted = false,
    this.isRunningOnEmulator = false,
    this.isHookingDetected = false,
    this.isNetworkIntercepted = false,
    this.isIntegrityCompromised = false,
    this.isMemoryTampered = false,
    this.isAccessibilityAbused = false,
    this.isDevToolsOpen = false,
    this.isAppBackgrounded = false,
    this.activeThreats = const [],
    this.lastEvent,
  });

  /// Whether secure mode is currently active (native flags enabled).
  final bool isSecureModeActive;

  /// Whether screen capture/recording is currently happening.
  final bool isScreenBeingCaptured;

  /// Whether a debugger is currently attached.
  final bool isDebuggerAttached;

  /// Whether the device is rooted (Android) or jailbroken (iOS).
  final bool isDeviceRooted;

  /// Whether the app is running on an emulator/VM.
  final bool isRunningOnEmulator;

  /// Whether function hooking (Frida, Xposed) is detected.
  final bool isHookingDetected;

  /// Whether network traffic is being intercepted.
  final bool isNetworkIntercepted;

  /// Whether the app binary integrity is compromised.
  final bool isIntegrityCompromised;

  /// Whether application memory has been externally modified.
  final bool isMemoryTampered;

  /// Whether an accessibility service is reading screen content.
  final bool isAccessibilityAbused;

  /// Whether browser DevTools are open (web only).
  final bool isDevToolsOpen;

  /// Whether the app is currently backgrounded.
  final bool isAppBackgrounded;

  /// List of currently active threat types.
  final List<SecurityEventType> activeThreats;

  /// Most recent security event received.
  final SecurityEvent? lastEvent;

  /// Whether the device/environment is considered safe for content display.
  ///
  /// Returns false if ANY compromise indicator is detected.
  /// When false, all secure content should be blurred or hidden.
  bool get isEnvironmentSafe =>
      !isDeviceRooted &&
      !isRunningOnEmulator &&
      !isHookingDetected &&
      !isIntegrityCompromised &&
      !isDebuggerAttached &&
      !isMemoryTampered &&
      !isAccessibilityAbused &&
      !isDevToolsOpen;

  /// Whether content should be blurred right now.
  ///
  /// True only during active screen capture/recording or when the app is
  /// backgrounded. Environment threats (root, emulator, debugger, etc.)
  /// are tracked for RASP scoring and audit logging but do NOT trigger
  /// content blur — content is shown normally until an active capture
  /// attempt is detected.
  bool get shouldBlurContent => isScreenBeingCaptured || isAppBackgrounded;

  /// Whether any threat is currently active.
  bool get hasActiveThreats => activeThreats.isNotEmpty;

  /// Apply a new security event and return updated state.
  ///
  /// Maps every [SecurityEventType] to its corresponding state flag.
  /// Events only set flags to true (threats are sticky until explicitly cleared).
  SecurityState applyEvent(SecurityEvent event) {
    final updatedThreats = List<SecurityEventType>.from(activeThreats);
    if (!updatedThreats.contains(event.type)) {
      updatedThreats.add(event.type);
    }

    return SecurityState(
      isSecureModeActive: isSecureModeActive,
      isScreenBeingCaptured: event.type == SecurityEventType.screenCapture
          ? true
          : isScreenBeingCaptured,
      isDebuggerAttached: event.type == SecurityEventType.debuggerAttached
          ? true
          : isDebuggerAttached,
      isDeviceRooted: event.type == SecurityEventType.rootDetected
          ? true
          : isDeviceRooted,
      isRunningOnEmulator: event.type == SecurityEventType.emulatorDetected
          ? true
          : isRunningOnEmulator,
      isHookingDetected: event.type == SecurityEventType.hookingDetected
          ? true
          : isHookingDetected,
      isNetworkIntercepted:
          event.type == SecurityEventType.networkInterception
              ? true
              : isNetworkIntercepted,
      isIntegrityCompromised:
          event.type == SecurityEventType.integrityViolation
              ? true
              : isIntegrityCompromised,
      isMemoryTampered: event.type == SecurityEventType.memoryTampering
          ? true
          : isMemoryTampered,
      isAccessibilityAbused:
          event.type == SecurityEventType.accessibilityAbuse
              ? true
              : isAccessibilityAbused,
      isDevToolsOpen: event.type == SecurityEventType.devToolsOpened
          ? true
          : isDevToolsOpen,
      isAppBackgrounded: event.type == SecurityEventType.appBackgrounded
          ? true
          : isAppBackgrounded,
      activeThreats: updatedThreats,
      lastEvent: event,
    );
  }

  /// Mark screen capture as cleared (recording stopped).
  SecurityState clearScreenCapture() {
    final updatedThreats = List<SecurityEventType>.from(activeThreats)
      ..remove(SecurityEventType.screenCapture);

    return _copyWith(
      isScreenBeingCaptured: false,
      activeThreats: updatedThreats,
    );
  }

  /// Update secure mode active status.
  SecurityState withSecureMode({required bool active}) {
    return _copyWith(isSecureModeActive: active);
  }

  /// Mark app as foregrounded (clear backgrounded state).
  SecurityState clearBackgrounded() {
    final updatedThreats = List<SecurityEventType>.from(activeThreats)
      ..remove(SecurityEventType.appBackgrounded);

    return _copyWith(
      isAppBackgrounded: false,
      activeThreats: updatedThreats,
    );
  }

  /// Internal copyWith to reduce duplication.
  SecurityState _copyWith({
    bool? isSecureModeActive,
    bool? isScreenBeingCaptured,
    bool? isDebuggerAttached,
    bool? isDeviceRooted,
    bool? isRunningOnEmulator,
    bool? isHookingDetected,
    bool? isNetworkIntercepted,
    bool? isIntegrityCompromised,
    bool? isMemoryTampered,
    bool? isAccessibilityAbused,
    bool? isDevToolsOpen,
    bool? isAppBackgrounded,
    List<SecurityEventType>? activeThreats,
    SecurityEvent? lastEvent,
  }) {
    return SecurityState(
      isSecureModeActive: isSecureModeActive ?? this.isSecureModeActive,
      isScreenBeingCaptured:
          isScreenBeingCaptured ?? this.isScreenBeingCaptured,
      isDebuggerAttached: isDebuggerAttached ?? this.isDebuggerAttached,
      isDeviceRooted: isDeviceRooted ?? this.isDeviceRooted,
      isRunningOnEmulator: isRunningOnEmulator ?? this.isRunningOnEmulator,
      isHookingDetected: isHookingDetected ?? this.isHookingDetected,
      isNetworkIntercepted: isNetworkIntercepted ?? this.isNetworkIntercepted,
      isIntegrityCompromised:
          isIntegrityCompromised ?? this.isIntegrityCompromised,
      isMemoryTampered: isMemoryTampered ?? this.isMemoryTampered,
      isAccessibilityAbused:
          isAccessibilityAbused ?? this.isAccessibilityAbused,
      isDevToolsOpen: isDevToolsOpen ?? this.isDevToolsOpen,
      isAppBackgrounded: isAppBackgrounded ?? this.isAppBackgrounded,
      activeThreats: activeThreats ?? this.activeThreats,
      lastEvent: lastEvent ?? this.lastEvent,
    );
  }
}
