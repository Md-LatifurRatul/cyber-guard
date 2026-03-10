import Foundation
import Darwin

/// Anti-debugging protections for iOS.
///
/// ## Why anti-debugging matters:
///
/// A debugger can:
///   - Inspect all memory, including decryption keys
///   - Modify variables at runtime (bypass security checks)
///   - Set breakpoints on security functions to skip them
///   - Dump the entire app state to disk
///
/// ## Two protection layers:
///
/// ### Layer 1: PT_DENY_ATTACH
/// A ptrace request that tells the kernel to refuse all future
/// debugger attachment attempts. Once called:
///   - LLDB can't attach to the process
///   - GDB can't attach to the process
///   - `debugserver` (iOS debug tool) gets rejected
///
/// We call this via `dlsym` to avoid the function appearing in
/// the static import table (which reverse engineers check first).
///
/// ### Layer 2: sysctl P_TRACED check
/// Even if PT_DENY_ATTACH is bypassed (some jailbreak tools patch it),
/// we can still detect debugging by checking the process flags via sysctl.
/// The P_TRACED flag is set by the kernel whenever ptrace attaches.
///
/// ## Important note:
/// These protections WILL interfere with Xcode debugging during development.
/// They should only be active in release builds. The `#if !DEBUG` guard
/// ensures this.
class AntiDebugProtection {

    /// Enable all anti-debug protections.
    func enableProtection() {
        #if !DEBUG
        denyDebuggerAttachment()
        #endif
    }

    /// Check if a debugger is currently attached.
    ///
    /// Uses sysctl to query the kernel for the process's kinfo_proc.
    /// The P_TRACED flag in kp_proc.p_flag indicates debugging.
    ///
    /// ## How sysctl works:
    /// sysctl is a kernel interface for reading system parameters.
    /// We ask for KERN_PROC info about our own PID.
    /// The kernel returns a kinfo_proc struct with process flags.
    /// If P_TRACED (0x00000800) is set, a debugger is attached.
    func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        if result != 0 {
            // sysctl failed — treat as suspicious
            return true
        }

        // P_TRACED flag check
        // kp_proc.p_flag contains process flags set by the kernel
        // P_TRACED (0x00000800) is set when ptrace is attached
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // MARK: - Private

    /// Prevent debugger attachment using PT_DENY_ATTACH.
    ///
    /// PT_DENY_ATTACH is a ptrace request specific to macOS/iOS.
    /// When called, the kernel marks the process as non-debuggable.
    /// Any future attach attempts will fail with EBUSY.
    ///
    /// We use dlsym to look up ptrace dynamically to avoid having
    /// "ptrace" appear in our import table (basic anti-reversing measure).
    private func denyDebuggerAttachment() {
        // PT_DENY_ATTACH = 31
        let PT_DENY_ATTACH: CInt = 31

        // Look up ptrace via dlsym to avoid static import detection
        typealias PtraceType = @convention(c) (CInt, pid_t, caddr_t?, CInt) -> CInt

        guard let handle = dlopen(nil, RTLD_NOW) else { return }
        defer { dlclose(handle) }

        guard let sym = dlsym(handle, "ptrace") else { return }

        let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
        let _ = ptraceFunc(PT_DENY_ATTACH, 0, nil, 0)
    }
}
