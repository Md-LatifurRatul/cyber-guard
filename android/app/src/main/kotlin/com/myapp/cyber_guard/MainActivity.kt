package com.myapp.cyber_guard

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

/**
 * Main entry point for the Android application.
 *
 * ## How Flutter plugin registration works:
 *
 * 1. Flutter creates the FlutterEngine (Dart VM + platform channels)
 * 2. `configureFlutterEngine()` is called — we register our plugin
 * 3. The plugin's `onAttachedToEngine()` sets up MethodChannel & EventChannel
 * 4. The plugin's `onAttachedToActivity()` gives it access to this Activity
 * 5. Now Dart can send method calls and receive events
 *
 * ## Why register manually instead of auto-registration:
 * Auto-registration uses GeneratedPluginRegistrant which works for pub.dev
 * packages. Since CyberGuard is built into the app (not a separate package),
 * we register it manually here for explicit control.
 */
class MainActivity : FlutterActivity() {

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Register the CyberGuard security plugin
        flutterEngine.plugins.add(CyberGuardPlugin())

        // Register the secure media player plugin
        flutterEngine.plugins.add(SecurePlayerPlugin())

        // Register the secure PDF plugin
        flutterEngine.plugins.add(SecurePdfPlugin())
    }
}
