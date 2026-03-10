import Foundation
import CommonCrypto
import MachO

/// Verifies the integrity of the running application binary.
///
/// ## Why integrity verification matters:
///
/// Attackers modify app binaries to:
/// - Remove security checks (patch out jailbreak detection)
/// - Inject malicious code (keyloggers, data exfiltration)
/// - Bypass license/subscription checks
/// - Disable SSL pinning for MitM attacks
///
/// ## Three verification layers:
///
/// ### 1. Code signing validation (macOS only)
/// Uses Security.framework's `SecStaticCodeCreateWithPath` to verify
/// the app's code signature against Apple's requirements. This detects:
/// - Re-signed binaries (different team ID)
/// - Modified executables (signature invalidated)
/// - Ad-hoc signed or unsigned binaries
///
/// Note: iOS doesn't expose `SecStaticCode` API, so we use alternative
/// checks on iOS (executable hash, encryption info).
///
/// ### 2. Executable hash verification
/// Compute SHA-256 of the main executable at runtime and compare against
/// a stored baseline. If the hash changes, the binary was modified.
/// This catches binary patches that code signing alone might miss
/// (e.g., if the attacker re-signs after patching).
///
/// ### 3. Mach-O encryption check (iOS only)
/// App Store apps have their __TEXT segment encrypted (FairPlay DRM).
/// A decrypted binary indicates the app was dumped from memory
/// (using tools like dumpdecrypted, Clutch, or frida-ios-dump).
/// We check the LC_ENCRYPTION_INFO load command for this.
///
/// ## Shared across iOS and macOS:
/// Uses conditional compilation (#if os(iOS) / #if os(macOS)) for
/// platform-specific checks, with shared hash verification.
class IntegrityVerifier {

    struct IntegrityResult {
        var codeSignatureValid: Bool = true
        var executableHashMatch: Bool = true
        var isEncrypted: Bool = true // iOS only, always true on macOS

        var isIntact: Bool {
            codeSignatureValid && executableHashMatch && isEncrypted
        }

        var failedChecks: String {
            var checks: [String] = []
            if !codeSignatureValid { checks.append("code_signature") }
            if !executableHashMatch { checks.append("executable_hash") }
            if !isEncrypted { checks.append("encryption") }
            return checks.joined(separator: ",")
        }
    }

    // MARK: - Baseline

    /// SHA-256 hash of the executable recorded at first launch.
    /// Stored in UserDefaults — if it changes between launches,
    /// the binary was tampered with.
    private static let hashStorageKey = "cg_exe_hash_baseline"

    /// Record the executable hash as baseline.
    /// Call once during initialization. Subsequent calls are no-ops
    /// if a baseline already exists.
    func establishBaseline() {
        let defaults = UserDefaults.standard
        guard defaults.string(forKey: IntegrityVerifier.hashStorageKey) == nil else {
            return // Baseline already established
        }

        if let hash = computeExecutableHash() {
            defaults.set(hash, forKey: IntegrityVerifier.hashStorageKey)
        }
    }

    /// Run all integrity verification checks.
    func verify() -> IntegrityResult {
        var result = IntegrityResult()

        // Check 1: Code signature (macOS only — iOS doesn't expose SecStaticCode)
        #if os(macOS)
        result.codeSignatureValid = verifyCodeSignature()
        #endif

        // Check 2: Executable hash
        result.executableHashMatch = verifyExecutableHash()

        // Check 3: Encryption (iOS only — macOS apps aren't encrypted)
        #if os(iOS)
        result.isEncrypted = checkEncryption()
        #endif

        return result
    }

    // MARK: - Check 1: Code Signature (macOS)

    #if os(macOS)
    /// Verify the app's code signature using Security.framework.
    ///
    /// ## How SecStaticCode works:
    ///
    /// 1. `SecStaticCodeCreateWithPath` creates a code object from the app bundle
    /// 2. `SecStaticCodeCheckValidity` verifies:
    ///    - The binary hasn't been modified since signing
    ///    - The certificate chain is valid
    ///    - The signature meets the specified requirements
    ///
    /// We use `kSecCSCheckAllArchitectures` to verify all slices in a
    /// universal binary, and `kSecCSStrictValidate` for strict checking.
    ///
    /// ## Why not on iOS:
    /// Apple removed `SecStaticCode` from the iOS SDK. The kernel enforces
    /// code signing on iOS anyway (AMFI), so a modified binary simply won't
    /// run on non-jailbroken devices. On jailbroken devices, AMFI is disabled,
    /// so neither our check nor the kernel's would help — we rely on
    /// jailbreak detection instead.
    private func verifyCodeSignature() -> Bool {
        guard let bundlePath = Bundle.main.bundlePath as CFString? else {
            return false
        }

        let bundleURL = CFURLCreateWithFileSystemPath(
            kCFAllocatorDefault,
            bundlePath,
            .cfurlposixPathStyle,
            true
        )

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            bundleURL!,
            SecCSFlags(),
            &staticCode
        )

        guard createStatus == errSecSuccess, let code = staticCode else {
            return false
        }

        // Validate with strict flags:
        // - kSecCSCheckAllArchitectures: Check all architectures in universal binary
        // - kSecCSStrictValidate: Strict validation (rejects some edge cases)
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        let validStatus = SecStaticCodeCheckValidity(code, flags, nil)

        return validStatus == errSecSuccess
    }
    #endif

    // MARK: - Check 2: Executable Hash

    /// Compute SHA-256 of the main executable and compare to baseline.
    ///
    /// ## How this works:
    /// 1. Get the path to the main executable from Bundle.main
    /// 2. Read the entire file into memory
    /// 3. Compute SHA-256 using CommonCrypto
    /// 4. Compare against the hash stored at first launch
    ///
    /// ## Why SHA-256:
    /// - Collision-resistant: Attacker can't create a different binary with same hash
    /// - Fast: ~100ms for a typical app binary (50-100MB)
    /// - Available via CommonCrypto (no third-party dependencies)
    private func verifyExecutableHash() -> Bool {
        guard let currentHash = computeExecutableHash() else {
            // Can't compute hash — treat as suspicious
            return false
        }

        guard let baselineHash = UserDefaults.standard.string(
            forKey: IntegrityVerifier.hashStorageKey
        ) else {
            // No baseline yet — first run, establish it and pass
            UserDefaults.standard.set(currentHash, forKey: IntegrityVerifier.hashStorageKey)
            return true
        }

        return currentHash == baselineHash
    }

    /// Compute SHA-256 hash of the main executable binary.
    private func computeExecutableHash() -> String? {
        guard let executablePath = Bundle.main.executablePath else {
            return nil
        }

        guard let data = FileManager.default.contents(atPath: executablePath) else {
            return nil
        }

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            _ = CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &hash)
        }

        return hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Check 3: Encryption (iOS)

    #if os(iOS)
    /// Check if the app binary is still encrypted (FairPlay DRM).
    ///
    /// ## How App Store encryption works:
    ///
    /// When Apple distributes an app through the App Store, the __TEXT
    /// segment of the Mach-O binary is encrypted with FairPlay DRM.
    /// The key is tied to the user's Apple ID.
    ///
    /// When the app launches, the kernel decrypts the __TEXT segment
    /// in memory. The on-disk binary remains encrypted.
    ///
    /// ## What we check:
    ///
    /// The `LC_ENCRYPTION_INFO_64` load command contains a `cryptid` field:
    /// - cryptid == 1: Binary is encrypted (App Store build)
    /// - cryptid == 0: Binary is decrypted (dumped or development build)
    ///
    /// A decrypted binary in production means someone used a tool like
    /// `dumpdecrypted`, `Clutch`, or `frida-ios-dump` to extract the
    /// unencrypted binary from memory.
    ///
    /// ## Note on development builds:
    /// During development (Xcode builds), cryptid is 0 because the binary
    /// isn't encrypted. We guard this with `#if !DEBUG` in the caller.
    private func checkEncryption() -> Bool {
        #if DEBUG
        // Development builds are never encrypted — skip this check
        return true
        #else
        let header = _dyld_get_image_header(0) // 0 = main executable
        guard let header = header else { return false }

        // Walk the load commands to find LC_ENCRYPTION_INFO_64
        var cursor = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header.pointee.ncmds {
            let cmd = cursor.assumingMemoryBound(to: load_command.self)

            if cmd.pointee.cmd == LC_ENCRYPTION_INFO_64 {
                let encryptionCmd = cursor.assumingMemoryBound(
                    to: encryption_info_command_64.self
                )
                // cryptid == 0 means decrypted (dumped)
                // cryptid == 1 means encrypted (App Store)
                return encryptionCmd.pointee.cryptid != 0
            }

            cursor = cursor.advanced(by: Int(cmd.pointee.cmdsize))
        }

        // No encryption load command found — might be a dev build
        return true
        #endif
    }
    #endif
}
