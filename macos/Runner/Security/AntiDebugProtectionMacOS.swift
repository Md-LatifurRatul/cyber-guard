import Foundation
import Darwin

/// Anti-debugging protections for macOS.
///
/// Same logic as iOS version. Separate file because macOS uses
/// a different framework import chain. The sysctl and ptrace
/// APIs work identically on both platforms.
class AntiDebugProtectionMacOS {

    func enableProtection() {
        #if !DEBUG
        denyDebuggerAttachment()
        #endif
    }

    /// Check if a debugger is currently attached via sysctl.
    func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        if result != 0 {
            return true
        }

        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private func denyDebuggerAttachment() {
        let PT_DENY_ATTACH: CInt = 31

        typealias PtraceType = @convention(c) (CInt, pid_t, caddr_t?, CInt) -> CInt

        guard let handle = dlopen(nil, RTLD_NOW) else { return }
        defer { dlclose(handle) }

        guard let sym = dlsym(handle, "ptrace") else { return }

        let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
        let _ = ptraceFunc(PT_DENY_ATTACH, 0, nil, 0)
    }
}
