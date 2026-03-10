import Foundation
import MachO

/// Monitors loaded dynamic libraries (dylibs) for injection attacks.
///
/// ## Why DYLD monitoring matters:
///
/// Hooking frameworks (Frida, Cycript, Substrate) work by injecting their
/// dylibs into the target process. On Apple platforms, every loaded library
/// is tracked by the dynamic linker (dyld). We can enumerate them using:
///   - `_dyld_image_count()` — total loaded images
///   - `_dyld_get_image_name(i)` — path of image at index i
///
/// ## Detection strategy:
///
/// 1. **Snapshot scan:** Enumerate all currently loaded images and check
///    against a list of known injection framework signatures.
/// 2. **Baseline monitoring:** Record the initial library count at startup.
///    If new libraries appear at runtime beyond what's expected, flag it.
///    Normal apps load all their dylibs at launch — new ones appearing
///    later strongly suggest injection.
///
/// ## Shared across iOS and macOS:
/// The dyld API is identical on both platforms. This class works on both
/// without any conditional compilation.
class DYLDMonitor {

    struct DYLDResult {
        var suspiciousLibrariesFound: Bool = false
        var unexpectedLibraryGrowth: Bool = false
        var suspiciousLibraryNames: [String] = []
        var baselineCount: UInt32 = 0
        var currentCount: UInt32 = 0

        var isCompromised: Bool {
            suspiciousLibrariesFound || unexpectedLibraryGrowth
        }

        var detectionMethods: String {
            var methods: [String] = []
            if suspiciousLibrariesFound { methods.append("suspicious_dylibs") }
            if unexpectedLibraryGrowth { methods.append("library_growth") }
            return methods.joined(separator: ",")
        }
    }

    // MARK: - Known injection framework signatures

    /// Library name substrings that indicate hooking/injection frameworks.
    /// ALL LOWERCASE — we convert image paths to lowercase before matching.
    ///
    /// Each entry targets a specific tool:
    /// - Frida: Dynamic instrumentation toolkit (security testing)
    /// - Cycript: JavaScript-Objective-C bridge for runtime inspection
    /// - Substrate: Cydia Substrate / Mobile Substrate (tweak injection)
    /// - Substitute: Open-source Substrate replacement
    /// - TweakInject: ElleKit-based tweak injector (modern jailbreaks)
    /// - SSLKillSwitch: Disables SSL pinning (exposes API traffic)
    /// - Reveal: UI inspection tool (leaks view hierarchy)
    /// - libinject: Generic injection libraries
    private static let suspiciousSignatures: [String] = [
        // Frida
        "frida",
        "fridaserver",
        "frida-agent",
        "frida-gadget",
        "libfrida",

        // Cycript
        "cycript",
        "libcycript",
        "cynject",

        // Substrate / Substitute
        "substrate",
        "libsubstrate",
        "mobilesubstrate",
        "substitute",
        "libsubstitute",
        "substitute-inserter",

        // TweakInject (ElleKit)
        "tweakinject",
        "ellekit",

        // SSL Pinning bypass
        "sslkillswitch",
        "ssl_kill_switch",

        // Reveal (UI inspector)
        "libreveal",
        "revealserver",

        // Shadow / Liberty (jailbreak bypass tools — presence = jailbroken)
        "libshadow",
        "liberty",
        "a-bypass",

        // Generic injection
        "libinject",
        "libhook",
    ]

    // MARK: - Baseline tracking

    /// Library count at initialization time.
    /// Normal apps load all dylibs at launch. Growth after this point
    /// is suspicious (new library injected at runtime).
    private var baselineImageCount: UInt32 = 0

    /// Maximum expected growth above baseline.
    /// Some legitimate growth can happen (lazy-loaded frameworks, plugins).
    /// We allow a small buffer to avoid false positives.
    private static let maxExpectedGrowth: UInt32 = 5

    // MARK: - Public API

    /// Record the current library count as the baseline.
    /// Call this during app initialization, before entering secure mode.
    func establishBaseline() {
        baselineImageCount = _dyld_image_count()
    }

    /// Run all DYLD injection detection checks.
    func detect() -> DYLDResult {
        let currentCount = _dyld_image_count()
        let suspiciousLibs = scanForSuspiciousLibraries()

        var result = DYLDResult()
        result.baselineCount = baselineImageCount
        result.currentCount = currentCount

        // Signal 1: Known injection framework libraries loaded
        if !suspiciousLibs.isEmpty {
            result.suspiciousLibrariesFound = true
            result.suspiciousLibraryNames = suspiciousLibs
        }

        // Signal 2: Unexpected library count growth
        // Only check if baseline was established (> 0)
        if baselineImageCount > 0 {
            let growth = currentCount > baselineImageCount
                ? currentCount - baselineImageCount
                : 0
            if growth > DYLDMonitor.maxExpectedGrowth {
                result.unexpectedLibraryGrowth = true
            }
        }

        return result
    }

    // MARK: - Private

    /// Enumerate all loaded images and check for suspicious library names.
    ///
    /// ## How _dyld_get_image_name works:
    /// Returns the full path of the Mach-O image at the given index.
    /// Example: "/usr/lib/libobjc.A.dylib"
    /// Frida injection would show: "/private/var/tmp/frida-agent-64.dylib"
    ///
    /// We check the full path (not just the filename) because some tools
    /// install to distinctive directories like /usr/lib/TweakInject/.
    private func scanForSuspiciousLibraries() -> [String] {
        var found: [String] = []
        let imageCount = _dyld_image_count()

        for i in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let path = String(cString: imageName).lowercased()

            for signature in DYLDMonitor.suspiciousSignatures {
                if path.contains(signature) {
                    // Store the original (non-lowercased) name for logging
                    found.append(String(cString: imageName))
                    break // One match per image is enough
                }
            }
        }

        return found
    }
}
