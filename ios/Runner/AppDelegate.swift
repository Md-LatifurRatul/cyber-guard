import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        // Register auto-generated plugins (from pubspec dependencies)
        GeneratedPluginRegistrant.register(with: self)

        // Register our custom security plugin
        if let registrar = self.registrar(forPlugin: "CyberGuardPlugin") {
            CyberGuardPlugin.register(with: registrar)
        }

        // Register the secure media player plugin
        if let registrar = self.registrar(forPlugin: "SecurePlayerPlugin") {
            SecurePlayerPlugin.register(with: registrar)
        }

        // Register the secure PDF plugin
        if let registrar = self.registrar(forPlugin: "SecurePdfPlugin") {
            SecurePdfPlugin.register(with: registrar)
        }

        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }
}
