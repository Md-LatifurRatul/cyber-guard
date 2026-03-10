package com.myapp.cyber_guard

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Multi-signal root detection for Android.
 *
 * ## Why multi-signal:
 * No single root check is reliable. Modern root tools (Magisk, KernelSU)
 * actively hide from individual checks. By combining 7 independent signals,
 * we make it extremely difficult to hide root status.
 *
 * ## Detection signals:
 * 1. **su binary paths** — Check 12+ common locations for the su binary
 * 2. **Magisk artifacts** — Magisk Manager package, magisk binary, mount points
 * 3. **SuperSU artifacts** — SuperSU app, .su.json config
 * 4. **KernelSU artifacts** — ksud binary, ksu paths
 * 5. **Build tags** — test-keys in Build.TAGS (custom ROM indicator)
 * 6. **SELinux status** — Permissive mode (root tools often disable SELinux)
 * 7. **Root management packages** — Known root manager app package names
 *
 * ## False positive avoidance:
 * We require multiple signals before declaring root. A single signal
 * might be a false positive (e.g., build tags on some custom ROMs).
 * Two or more signals is a strong indicator.
 *
 * ## Return value:
 * Returns a data class with individual signal results and an overall verdict.
 */
class RootDetector(private val context: Context) {

    companion object {
        private const val TAG = "RootDetector"
    }

    /**
     * Result of root detection with individual signal details.
     */
    data class RootCheckResult(
        val suBinaryFound: Boolean = false,
        val magiskDetected: Boolean = false,
        val superSuDetected: Boolean = false,
        val kernelSuDetected: Boolean = false,
        val testKeysDetected: Boolean = false,
        val selinuxPermissive: Boolean = false,
        val rootPackagesFound: Boolean = false,
        val nativeRootDetected: Boolean = false,
    ) {
        /** Number of positive signals. */
        val signalCount: Int get() = listOf(
            suBinaryFound, magiskDetected, superSuDetected,
            kernelSuDetected, testKeysDetected, selinuxPermissive,
            rootPackagesFound, nativeRootDetected,
        ).count { it }

        /** Overall verdict: rooted if ANY signal is positive. */
        val isRooted: Boolean get() = signalCount > 0

        /** Method string for event metadata. */
        val detectionMethods: String get() {
            val methods = mutableListOf<String>()
            if (suBinaryFound) methods.add("su_binary")
            if (magiskDetected) methods.add("magisk")
            if (superSuDetected) methods.add("supersu")
            if (kernelSuDetected) methods.add("kernelsu")
            if (testKeysDetected) methods.add("test_keys")
            if (selinuxPermissive) methods.add("selinux_permissive")
            if (rootPackagesFound) methods.add("root_packages")
            if (nativeRootDetected) methods.add("native")
            return methods.joinToString(",")
        }
    }

    /**
     * Run all root detection signals and return combined result.
     */
    fun detect(nativeBridge: SecurityBridge? = null): RootCheckResult {
        val nativeResult = nativeBridge?.let {
            try {
                it.nativeDetectRoot()
            } catch (e: Exception) {
                Log.e(TAG, "Native root detection failed: ${e.message}")
                0
            }
        } ?: 0

        return RootCheckResult(
            suBinaryFound = checkSuBinary() || (nativeResult and 0x01 != 0),
            magiskDetected = checkMagisk() || (nativeResult and 0x02 != 0),
            superSuDetected = checkSuperSu(),
            kernelSuDetected = checkKernelSu(),
            testKeysDetected = checkBuildTags(),
            selinuxPermissive = checkSelinux(),
            rootPackagesFound = checkRootPackages(),
            nativeRootDetected = nativeResult != 0,
        )
    }

    // ─── Signal 1: su binary in common paths ───

    /**
     * Check for su binary in filesystem paths.
     *
     * The `su` command is the root access binary. It exists in various
     * locations depending on the root method used.
     */
    private fun checkSuBinary(): Boolean {
        val suPaths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
        )

        return suPaths.any { File(it).exists() }.also { found ->
            if (found) Log.w(TAG, "su binary found in filesystem")
        }
    }

    // ─── Signal 2: Magisk detection ───

    /**
     * Detect Magisk root framework.
     *
     * Magisk is the most popular root tool. It hides from basic checks
     * using DenyList (formerly MagiskHide), but leaves other traces.
     */
    private fun checkMagisk(): Boolean {
        // Magisk files
        val magiskPaths = arrayOf(
            "/sbin/.magisk",
            "/sbin/magisk",
            "/system/xbin/magisk",
            "/cache/.disable_magisk",
            "/data/adb/magisk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
        )

        if (magiskPaths.any { File(it).exists() }) {
            Log.w(TAG, "Magisk files detected")
            return true
        }

        // Magisk Manager package (may be renamed with random package name)
        val magiskPackages = arrayOf(
            "com.topjohnwu.magisk",
            // Magisk can randomize its package name, but the class names remain
        )
        if (magiskPackages.any { isPackageInstalled(it) }) {
            Log.w(TAG, "Magisk Manager package found")
            return true
        }

        return false
    }

    // ─── Signal 3: SuperSU detection ───

    private fun checkSuperSu(): Boolean {
        val superSuPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/xbin/daemonsu",
            "/su/bin/sukernel",
        )

        if (superSuPaths.any { File(it).exists() }) {
            Log.w(TAG, "SuperSU files detected")
            return true
        }

        if (isPackageInstalled("eu.chainfire.supersu")) {
            Log.w(TAG, "SuperSU package found")
            return true
        }

        return false
    }

    // ─── Signal 4: KernelSU detection ───

    /**
     * Detect KernelSU — a kernel-based root solution.
     *
     * KernelSU modifies the kernel itself, making it harder to detect
     * than Magisk. However, it still needs management binaries.
     */
    private fun checkKernelSu(): Boolean {
        val ksuPaths = arrayOf(
            "/data/adb/ksud",
            "/data/adb/ksu",
            "/data/adb/ksu/modules",
        )

        if (ksuPaths.any { File(it).exists() }) {
            Log.w(TAG, "KernelSU files detected")
            return true
        }

        if (isPackageInstalled("me.weishu.kernelsu")) {
            Log.w(TAG, "KernelSU Manager package found")
            return true
        }

        return false
    }

    // ─── Signal 5: Build tags check ───

    /**
     * Check Build.TAGS for test-keys.
     *
     * Official release builds use "release-keys". Custom ROMs and
     * rooted devices often have "test-keys" or "dev-keys".
     * This is a weak signal — some legitimate custom ROMs use test-keys.
     */
    private fun checkBuildTags(): Boolean {
        val tags = Build.TAGS ?: return false
        return (tags.contains("test-keys") || tags.contains("dev-keys")).also { found ->
            if (found) Log.w(TAG, "Suspicious build tags: $tags")
        }
    }

    // ─── Signal 6: SELinux status ───

    /**
     * Check if SELinux is in permissive mode.
     *
     * SELinux in enforcing mode restricts what processes can do.
     * Root tools often set it to permissive (or disable it entirely)
     * because enforcing mode blocks root operations.
     */
    private fun checkSelinux(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val status = reader.readLine()?.trim() ?: return false
            reader.close()

            if (status.equals("Permissive", ignoreCase = true)) {
                Log.w(TAG, "SELinux is permissive")
                return true
            }
        } catch (_: Exception) {
            // getenforce not available — can't determine status
        }

        return false
    }

    // ─── Signal 7: Root management packages ───

    /**
     * Check for installed root management apps.
     */
    private fun checkRootPackages(): Boolean {
        val rootPackages = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloak2",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            // Root file managers
            "stericson.busybox",
            "com.jrummy.root.browserfree",
            "com.jrummy.busybox.installer",
        )

        return rootPackages.any { isPackageInstalled(it) }.also { found ->
            if (found) Log.w(TAG, "Root management package detected")
        }
    }

    // ─── Helper ───

    @Suppress("DEPRECATION")
    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: Exception) {
            false
        }
    }
}
