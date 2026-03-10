import 'dart:async';

import 'package:flutter/material.dart';

import 'core/security/security_channel.dart';
import 'core/security/security_state.dart';
import 'demo/screens/home/home_screen.dart';
import 'demo/screens/splash/splash_screen.dart';
import 'demo/theme/app_theme.dart';

/// Root application widget for CyberGuard.
///
/// Wraps the entire app with security state monitoring.
/// Listens to [SecurityChannel.stateStream] and provides the current
/// [SecurityState] to the widget tree via [CyberGuardApp.of(context)].
class CyberGuardApp extends StatefulWidget {
  const CyberGuardApp({super.key});

  /// Access the current security state from anywhere in the widget tree.
  static SecurityState? of(BuildContext context) {
    final scope =
        context.dependOnInheritedWidgetOfExactType<_SecurityScope>();
    return scope?.state;
  }

  @override
  State<CyberGuardApp> createState() => _CyberGuardAppState();
}

class _CyberGuardAppState extends State<CyberGuardApp>
    with WidgetsBindingObserver {
  SecurityState _securityState = const SecurityState();
  StreamSubscription<SecurityState>? _stateSubscription;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);

    // Listen to security state changes from native
    _stateSubscription = SecurityChannel.instance.stateStream.listen(
      _onSecurityStateChanged,
    );
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSubscription?.cancel();
    super.dispose();
  }

  /// React to app lifecycle changes.
  ///
  /// When app goes to background: notify native to protect task switcher.
  /// When app returns to foreground: re-verify security state.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
        // App is not visible — protect against task switcher screenshots
        // and split-screen content leaks.
        SecurityChannel.instance.notifyAppBackgrounded();
      case AppLifecycleState.resumed:
        SecurityChannel.instance.notifyAppForegrounded();
      case AppLifecycleState.detached:
        // App is being destroyed — clean up security resources.
        SecurityChannel.instance.dispose();
    }
  }

  void _onSecurityStateChanged(SecurityState state) {
    setState(() {
      _securityState = state;
    });
  }

  @override
  Widget build(BuildContext context) {
    return _SecurityScope(
      state: _securityState,
      child: MaterialApp(
        title: 'CyberGuard',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.darkTheme,
        darkTheme: AppTheme.darkTheme,
        home: const _AppShell(),
      ),
    );
  }
}

/// Shell widget that shows splash → home transition.
class _AppShell extends StatefulWidget {
  const _AppShell();

  @override
  State<_AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<_AppShell> {
  bool _splashComplete = false;

  @override
  Widget build(BuildContext context) {
    if (!_splashComplete) {
      return SplashScreen(
        onComplete: () => setState(() => _splashComplete = true),
      );
    }
    return const HomeScreen();
  }
}

/// InheritedWidget that provides [SecurityState] down the widget tree.
///
/// Rebuilds dependents whenever [state] changes, so widgets that call
/// `CyberGuardApp.of(context)` automatically react to security events.
class _SecurityScope extends InheritedWidget {
  const _SecurityScope({
    required this.state,
    required super.child,
  });

  final SecurityState state;

  @override
  bool updateShouldNotify(_SecurityScope oldWidget) =>
      state != oldWidget.state;
}

