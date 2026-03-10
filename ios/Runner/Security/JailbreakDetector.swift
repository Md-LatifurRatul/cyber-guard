import Foundation
import UIKit
import Darwin
import MachO

/// Multi-signal jailbreak detection for iOS.
///
/// ## Why multi-signal:
/// No single jailbreak check is reliable. Modern jailbreaks (checkra1n, unc0ver,
/// Taurine, Dopamine) actively hide from individual checks using tools like
/// Liberty Lite, Shadow, and A-Bypass. By combining 7 independent signals,
/// we make it extremely difficult to hide jailbreak status.
///
/// ## Detection signals:
/// 1. **Jailbreak file paths** — Check 20+ paths for Cydia, Substrate, etc.
/// 2. **URL scheme check** — cydia://, sileo://, zebra://
/// 3. **Sandbox escape** — Try writing outside the app sandbox
/// 4. **fork() test** — fork() should fail on non-jailbroken iOS
/// 5. **Suspicious dylibs** — Check loaded libraries for injection frameworks
/// 6. **Symbolic link check** — /Applications is symlinked on some jailbreaks
/// 7. **Environment variables** — DYLD_INSERT_LIBRARIES indicates injection
///
/// ## False positive avoidance:
/// We return individual signal results so the caller can decide the threshold.
/// Any single positive signal is suspicious, but sandbox and fork tests
/// are the strongest indicators.
class JailbreakDetector {

    struct JailbreakResult {
        var suspiciousFilesFound: Bool = false
        var jailbreakUrlSchemes: Bool = false
        var sandboxEscaped: Bool = false
        var forkSucceeded: Bool = false
        var suspiciousDylibs: Bool = false
        var symbolicLinksDetected: Bool = false
        var environmentTampered: Bool = false

        var signalCount: Int {
            [suspiciousFilesFound, jailbreakUrlSchemes, sandboxEscaped,
             forkSucceeded, suspiciousDylibs, symbolicLinksDetected,
             environmentTampered].filter { $0 }.count
        }

        /// Any single signal means jailbroken.
        var isJailbroken: Bool { signalCount > 0 }

        var detectionMethods: String {
            var methods: [String] = []
            if suspiciousFilesFound { methods.append("files") }
            if jailbreakUrlSchemes { methods.append("url_schemes") }
            if sandboxEscaped { methods.append("sandbox_escape") }
            if forkSucceeded { methods.append("fork") }
            if suspiciousDylibs { methods.append("dylibs") }
            if symbolicLinksDetected { methods.append("symlinks") }
            if environmentTampered { methods.append("environment") }
            return methods.joined(separator: ",")
        }
    }

    /// Run all jailbreak detection signals.
    func detect() -> JailbreakResult {
        return JailbreakResult(
            suspiciousFilesFound: checkSuspiciousFiles(),
            jailbreakUrlSchemes: checkUrlSchemes(),
            sandboxEscaped: checkSandboxEscape(),
            forkSucceeded: checkFork(),
            suspiciousDylibs: checkDylibs(),
            symbolicLinksDetected: checkSymbolicLinks(),
            environmentTampered: checkEnvironment()
        )
    }

    // MARK: - Signal 1: Suspicious file paths

    /// Check for jailbreak-related files in the filesystem.
    ///
    /// These files are installed by jailbreak tools and their managers.
    /// Each jailbreak method leaves different artifacts.
    private func checkSuspiciousFiles() -> Bool {
        let suspiciousPaths = [
            // Cydia (classic jailbreak app store)
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/var/cache/apt",
            "/var/lib/cydia",
            "/var/lib/apt",
            "/usr/sbin/sshd",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/etc/apt",
            "/etc/apt/sources.list.d",

            // Sileo (modern jailbreak package manager)
            "/Applications/Sileo.app",
            "/var/jb/Applications/Sileo.app",

            // Zebra (another package manager)
            "/Applications/Zebra.app",

            // Substrate / Substitute
            "/Library/MobileSubstrate",
            "/usr/lib/libsubstitute.0.dylib",
            "/usr/lib/substitute-inserter.dylib",
            "/usr/lib/TweakInject",

            // General jailbreak artifacts
            "/bin/bash",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib",
            "/var/jb",                          // rootless jailbreaks
            "/var/binpack",                     // unc0ver
            "/var/checkra1n.dmg",               // checkra1n
            "/.bootstrapped",                   // Taurine
            "/.installed_taurine",              // Taurine
            "/.installed_dopamine",             // Dopamine

            // su binary
            "/usr/bin/su",
            "/bin/su",

            // Jailbreak bypass tools (their presence = device IS jailbroken)
            "/Library/PreferenceBundles/LibertyPref.bundle",
            "/Library/PreferenceBundles/ShadowPreferences.bundle",
            "/Library/PreferenceBundles/ABypassPrefs.bundle",
        ]

        return suspiciousPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    // MARK: - Signal 2: URL scheme check

    /// Check if jailbreak package managers can be opened.
    ///
    /// On a non-jailbroken device, canOpenURL returns false for these
    /// because no app is registered to handle these URL schemes.
    private func checkUrlSchemes() -> Bool {
        let schemes = [
            "cydia://package/com.example.package",
            "sileo://package/com.example.package",
            "zbra://packages/com.example.package",
            "filza://view/var",
        ]

        return schemes.contains { scheme in
            if let url = URL(string: scheme) {
                return UIApplication.shared.canOpenURL(url)
            }
            return false
        }
    }

    // MARK: - Signal 3: Sandbox escape test

    /// Try writing a file outside the app sandbox.
    ///
    /// On non-jailbroken iOS, the app is confined to its own container.
    /// Any attempt to write outside it (e.g., to /private/var/tmp/) fails.
    /// If the write succeeds, the sandbox has been compromised.
    private func checkSandboxEscape() -> Bool {
        let testPath = "/private/var/tmp/cyberguard_jb_test"
        let testData = "jb_check".data(using: .utf8)!

        let success = FileManager.default.createFile(
            atPath: testPath,
            contents: testData,
            attributes: nil
        )

        if success {
            // Clean up the test file
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        }

        return false
    }

    // MARK: - Signal 4: fork() test

    /// Test if fork() succeeds.
    ///
    /// On non-jailbroken iOS, fork() always fails because the sandbox
    /// prevents process creation. If fork() succeeds, the sandbox
    /// has been broken, which is a strong jailbreak indicator.
    ///
    /// We immediately kill the child process if fork succeeds to
    /// avoid leaving orphan processes.
    ///
    /// ## Why dlsym instead of direct call:
    /// Swift marks fork() as unavailable on iOS. But fork() still exists
    /// in libSystem — it just returns -1 on non-jailbroken devices.
    /// We look it up via dlsym (same technique as ptrace in AntiDebugProtection)
    /// to bypass the Swift compiler restriction.
    private func checkFork() -> Bool {
        typealias ForkType = @convention(c) () -> Int32

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        guard let sym = dlsym(handle, "fork") else { return false }

        let forkFunc = unsafeBitCast(sym, to: ForkType.self)
        let pid = forkFunc()

        if pid >= 0 {
            if pid > 0 {
                // Parent: kill the child immediately
                kill(pid, SIGTERM)
            } else {
                // Child: exit immediately
                _exit(0)
            }
            return true // fork succeeded = jailbroken
        }
        return false // fork failed = normal (not jailbroken)
    }

    // MARK: - Signal 5: Suspicious dylibs

    /// Check loaded dylibs for injection framework signatures.
    ///
    /// Uses the dyld API to enumerate all loaded images (libraries).
    /// Frida, Cycript, Substrate, and other tools inject their dylibs
    /// into the process, and they appear in this list.
    private func checkDylibs() -> Bool {
        let suspiciousLibs = [
            "frida",
            "cynject",
            "cycript",
            "libcycript",
            "substrate",
            "SubstrateLoader",
            "SubstrateInserter",
            "TweakInject",
            "libsubstitute",
            "substitute-inserter",
            "SSLKillSwitch",
            "MobileSubstrate",
            "libReveal",
            "RevealServer",
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName).lowercased()

            for lib in suspiciousLibs {
                if name.contains(lib.lowercased()) {
                    return true
                }
            }
        }

        return false
    }

    // MARK: - Signal 6: Symbolic link check

    /// Check if system directories are symbolic links.
    ///
    /// Some jailbreaks (especially stashing-based ones) replace
    /// /Applications with a symlink to /var/stash/Applications.
    /// On stock iOS, /Applications is a real directory.
    private func checkSymbolicLinks() -> Bool {
        let pathsToCheck = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
        ]

        let fm = FileManager.default
        return pathsToCheck.contains { path in
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: path, isDirectory: &isDir) {
                // Check if it's a symbolic link
                if let attrs = try? fm.attributesOfItem(atPath: path),
                   let type = attrs[.type] as? FileAttributeType,
                   type == .typeSymbolicLink {
                    return true
                }
            }
            return false
        }
    }

    // MARK: - Signal 7: Environment variables

    /// Check for suspicious environment variables.
    ///
    /// DYLD_INSERT_LIBRARIES is used to inject dylibs into processes.
    /// On non-jailbroken iOS, this variable is ignored by the kernel,
    /// but on jailbroken devices it's used by Substrate and similar tools.
    private func checkEnvironment() -> Bool {
        let suspiciousVars = [
            "DYLD_INSERT_LIBRARIES",
            "_MSSafeMode",
            "SUBSTRATE_LIBRARY",
        ]

        return suspiciousVars.contains { ProcessInfo.processInfo.environment[$0] != nil }
    }
}
