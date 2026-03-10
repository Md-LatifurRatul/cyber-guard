//! Cross-Platform Security Detection Module
//!
//! ## What this detects:
//!
//! 1. **Known recording processes** — OBS, Fraps, Bandicam, etc.
//! 2. **Hooking framework signatures** — Frida, Xposed, Substrate
//! 3. **Memory integrity** — Simple checksum verification
//!
//! ## Platform differences:
//!
//! - **Android:** Uses /proc filesystem (C++ JNI already handles this,
//!   but Rust provides a secondary check via FFI)
//! - **macOS:** Full process enumeration via sysctl
//! - **iOS:** Sandboxed — can only check own process, not others
//! - **Web:** N/A — handled by JavaScript DevTools detection
//!
//! The Rust layer provides cross-platform logic that compiles to
//! native code on each platform. Platform-specific syscalls use
//! conditional compilation (`#[cfg(target_os)]`).

/// Known screen recording process names.
///
/// This list is checked against running processes on platforms that
/// allow process enumeration (Android via /proc, macOS via sysctl).
const CAPTURE_PROCESSES: &[&str] = &[
    // Desktop recording tools
    "obs",
    "obs64",
    "obs-studio",
    "OBS",
    "streamlabs",
    "ffmpeg",
    "vlc",
    "screenflow",
    "camtasia",
    "bandicam",
    "fraps",
    "xsplit",
    "action!",
    "dxtory",
    "nvidia shadowplay",
    "geforce experience",
    // macOS built-in
    "screencaptureui",
    "Screenshot",
    "QuickTime Player",
    // Android-specific (checked via JNI, listed here for completeness)
    "az_screen_recorder",
    "com.duapps.recorder",
    "com.hecorat.screenrecorder",
    "com.kimcy929.screenrecorder",
    "com.nll.screenrecorder",
];

/// Known hooking/instrumentation framework artifacts.
///
/// These strings appear in process names, library paths, or environment
/// variables when hooking frameworks are active.
const HOOK_SIGNATURES: &[&str] = &[
    // Frida (dynamic instrumentation)
    "frida",
    "frida-server",
    "frida-agent",
    "frida-gadget",
    "libfrida",
    // Xposed Framework (Android)
    "xposed",
    "de.robv.android.xposed",
    "XposedBridge",
    // Cydia Substrate (iOS jailbreak)
    "substrate",
    "SubstrateLoader",
    "MobileSubstrate",
    "libsubstrate",
    // LSPosed (modern Xposed successor)
    "lsposed",
    "lspd",
    // Magisk (Android root)
    "magisk",
    "su",
    // Generic
    "inject",
    "hook",
    "GameGuardian",
    "gameguardian",
];

/// Check if a process name matches any known capture tool.
///
/// Matching logic: exact match, path suffix match (e.g. "/obs"),
/// or space-separated word match. Avoids substring false positives
/// like "obsidian" matching "obs".
pub fn is_capture_process(process_name: &str) -> bool {
    let lower = process_name.to_lowercase();
    CAPTURE_PROCESSES.iter().any(|&known| {
        let k = known.to_lowercase();
        // Exact match
        lower == k
            // Path suffix: "/obs" at end
            || lower.ends_with(&format!("/{}", k))
            // Space-separated: "some obs process"
            || lower.starts_with(&format!("{} ", k))
            || lower.contains(&format!(" {} ", k))
            || lower.ends_with(&format!(" {}", k))
            // Package name: "com.obs.studio"
            || lower.contains(&format!(".{}.", k))
            || lower.ends_with(&format!(".{}", k))
            || lower.starts_with(&format!("{}.", k))
    })
}

/// Check if a string matches any known hooking framework signature.
///
/// Uses substring matching because hook artifacts can appear anywhere
/// in library paths (e.g. "/data/local/tmp/frida-server-16.0").
/// Hook signatures are specific enough to avoid false positives.
pub fn is_hook_signature(target: &str) -> bool {
    let lower = target.to_lowercase();
    HOOK_SIGNATURES.iter().any(|&sig| lower.contains(&sig.to_lowercase()))
}

/// Compute a simple checksum over a memory region.
///
/// Used for integrity verification — if someone patches our code
/// in memory, the checksum will change.
///
/// Uses FNV-1a (Fowler-Noll-Vo) hash — fast, non-cryptographic,
/// good distribution. We don't need cryptographic strength here,
/// just tamper detection.
pub fn compute_checksum(data: &[u8]) -> u64 {
    // FNV-1a 64-bit
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Verify a memory region's checksum against a known value.
///
/// # Returns
/// `true` if the checksum matches (memory is intact).
pub fn verify_checksum(data: &[u8], expected: u64) -> bool {
    compute_checksum(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_process_detection() {
        // Exact match
        assert!(is_capture_process("obs"));
        assert!(is_capture_process("OBS"));
        // Path suffix
        assert!(is_capture_process("/usr/bin/obs"));
        // Space-separated
        assert!(is_capture_process("OBS Studio"));
        assert!(is_capture_process("ffmpeg -f screen"));
        // Package name
        assert!(is_capture_process("com.obs.studio"));
        // Exact process name
        assert!(is_capture_process("screencaptureui"));

        // Should NOT match (substring false positives)
        assert!(!is_capture_process("obsidian"));
        assert!(!is_capture_process("chrome"));
        assert!(!is_capture_process("safari"));
        assert!(!is_capture_process("notepad"));
    }

    #[test]
    fn test_hook_signature_detection() {
        assert!(is_hook_signature("frida-server"));
        assert!(is_hook_signature("/data/local/tmp/frida"));
        assert!(is_hook_signature("libfrida-gadget.so"));
        assert!(is_hook_signature("de.robv.android.xposed.installer"));
        assert!(is_hook_signature("MobileSubstrate"));
        assert!(is_hook_signature("magisk"));

        assert!(!is_hook_signature("chrome"));
        assert!(!is_hook_signature("normal-app"));
    }

    #[test]
    fn test_checksum_consistency() {
        let data = b"CyberGuard integrity check";

        let checksum1 = compute_checksum(data);
        let checksum2 = compute_checksum(data);

        assert_eq!(checksum1, checksum2, "Same data should produce same checksum");
    }

    #[test]
    fn test_checksum_detects_modification() {
        let data = b"Original code bytes";
        let checksum = compute_checksum(data);

        let mut modified = data.to_vec();
        modified[5] ^= 0x01; // Flip one bit

        assert!(!verify_checksum(&modified, checksum));
    }

    #[test]
    fn test_checksum_empty() {
        let data = b"";
        let checksum = compute_checksum(data);
        assert!(verify_checksum(data, checksum));
    }
}
