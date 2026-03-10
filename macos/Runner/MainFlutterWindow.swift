import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)

    // Register CyberGuard security plugin
    CyberGuardPluginMacOS.register(
      with: flutterViewController.registrar(forPlugin: "CyberGuardPluginMacOS")
    )

    // Register secure media player plugin
    SecurePlayerPluginMacOS.register(
      with: flutterViewController.registrar(forPlugin: "SecurePlayerPluginMacOS")
    )

    // Register secure PDF plugin
    SecurePdfPluginMacOS.register(
      with: flutterViewController.registrar(forPlugin: "SecurePdfPluginMacOS")
    )

    super.awakeFromNib()
  }
}
