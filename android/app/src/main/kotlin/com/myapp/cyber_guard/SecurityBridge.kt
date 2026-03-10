package com.myapp.cyber_guard

import android.util.Log

/**
 * JNI Bridge to C++ native security code.
 *
 * ## How JNI works:
 * 1. `System.loadLibrary("security_core")` loads the .so file compiled from C++
 * 2. `external fun` declares a Kotlin function implemented in C++
 * 3. The JNI runtime matches function names by convention:
 *    Kotlin: `com.myapp.cyber_guard.SecurityBridge.nativeInit`
 *    C++:    `Java_com_myapp_cyber_1guard_SecurityBridge_nativeInit`
 *
 * ## Why a separate bridge class:
 * - Isolates native code loading from the Flutter plugin
 * - If the .so fails to load, only this class throws — plugin stays alive
 * - Makes testing easier (can mock this class)
 */
class SecurityBridge {

    companion object {
        private const val TAG = "CyberGuardBridge"
        private var isLoaded = false

        /**
         * Load the native library. Must be called before any native methods.
         *
         * We use a flag to prevent double-loading which would crash the app.
         * Loading happens in a try-catch because the .so might not exist
         * on certain architectures or in test environments.
         */
        fun loadNativeLibrary(): Boolean {
            if (isLoaded) return true

            return try {
                System.loadLibrary("security_core")
                isLoaded = true
                Log.i(TAG, "Native security library loaded successfully")
                true
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library: ${e.message}")
                false
            }
        }
    }

    // ─── Native method declarations ───
    // Implemented in security_core.cpp

    /** Initialize native security (anti-debug, etc.) */
    external fun nativeInit()

    /** Scan /proc for screen capture processes. Returns true if found. */
    external fun nativeDetectScreenCapture(): Boolean

    /** Check if a debugger is attached via /proc/self/status. */
    external fun nativeIsDebuggerAttached(): Boolean

    /** Re-enable anti-debug protections. */
    external fun nativeEnableAntiDebug()

    // Implemented in anti_hook.cpp

    /**
     * Detect hooking frameworks at native level.
     *
     * Returns a bitmask:
     *   Bit 0 (0x01): Hook library in /proc/self/maps
     *   Bit 1 (0x02): Frida port (27042-27052) open
     *   Bit 2 (0x04): Frida threads detected
     *   Bit 3 (0x08): Inline hooks on libc functions
     *
     * Returns 0 if no hooks detected.
     */
    external fun nativeDetectHooks(): Int

    /**
     * Root detection at native level.
     *
     * Returns a bitmask:
     *   Bit 0 (0x01): su binary found
     *   Bit 1 (0x02): Magisk traces in mounts
     *
     * Returns 0 if no root detected.
     */
    external fun nativeDetectRoot(): Int
}
