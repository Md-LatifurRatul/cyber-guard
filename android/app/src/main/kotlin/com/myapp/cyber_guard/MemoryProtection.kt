package com.myapp.cyber_guard

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Memory and APK integrity verification.
 *
 * ## What this protects against:
 * - APK repackaging (decompile → modify → recompile)
 * - Runtime code injection (Frida gadget embedded in APK)
 * - DEX file modification (patching Dalvik bytecode)
 * - Native library replacement (.so files swapped)
 *
 * ## How it works:
 *
 * ### APK Signature Verification
 * Every Android app is signed with a certificate. If the APK is modified
 * and re-signed, the certificate changes. We compute a hash of our
 * signing certificate at build time and verify it at runtime.
 *
 * ### DEX File Integrity
 * We compute SHA-256 of our classes.dex at first run and store it.
 * On subsequent runs, we recompute and compare. If the DEX has been
 * modified (e.g., Xposed module patches), the hash won't match.
 *
 * ### /proc/self/maps Monitoring
 * We periodically check our own memory maps for unexpected libraries.
 * If a new .so appears that wasn't loaded by us, it's injection.
 */
class MemoryProtection(private val context: Context) {

    companion object {
        private const val TAG = "MemoryProtection"
        private const val PREFS_NAME = "cg_integrity"
        private const val KEY_DEX_HASH = "dex_sha256"
        private const val KEY_INITIAL_LIB_COUNT = "initial_lib_count"
    }

    private var initialDexHash: String? = null
    private var initialLibraryCount: Int = 0
    private val prefs by lazy { context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }

    /**
     * Initialize integrity baselines.
     *
     * Call this once during app startup. On first run, it computes and stores
     * the baseline. On subsequent runs, it loads the stored baseline.
     */
    fun initialize() {
        // Compute current DEX hash
        val currentDexHash = computeDexHash()

        // Check if we have a stored baseline
        val storedHash = prefs.getString(KEY_DEX_HASH, null)
        if (storedHash == null && currentDexHash != null) {
            // First run — store baseline
            prefs.edit()
                .putString(KEY_DEX_HASH, currentDexHash)
                .putInt(KEY_INITIAL_LIB_COUNT, countLoadedLibraries())
                .apply()
            Log.i(TAG, "Integrity baseline established")
        }

        initialDexHash = storedHash ?: currentDexHash
        initialLibraryCount = prefs.getInt(KEY_INITIAL_LIB_COUNT, countLoadedLibraries())
    }

    /**
     * Verify APK signing certificate integrity.
     *
     * If the APK was re-signed (repackaged), the certificate hash changes.
     * We compare against a known-good hash.
     *
     * @param expectedCertHash SHA-256 of the expected signing certificate,
     *        or null to skip this check (useful during development).
     * @return true if certificate matches or check is skipped.
     */
    @Suppress("DEPRECATION")
    fun verifySignature(expectedCertHash: String? = null): Boolean {
        if (expectedCertHash == null) return true

        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES,
            )

            val signatures = packageInfo.signatures
            if (signatures.isNullOrEmpty()) {
                Log.w(TAG, "No signatures found — APK may be unsigned")
                return false
            }

            val certBytes = signatures[0].toByteArray()
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(certBytes)
            val hexHash = hash.joinToString("") { "%02x".format(it) }

            val matches = hexHash.equals(expectedCertHash, ignoreCase = true)
            if (!matches) {
                Log.w(TAG, "Certificate mismatch — APK may be repackaged")
            }
            return matches
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification failed: ${e.message}")
            return false
        }
    }

    /**
     * Verify DEX file integrity.
     *
     * Computes SHA-256 of classes.dex and compares against the baseline
     * stored during first run. DEX modification indicates:
     * - Repackaged APK with patched bytecode
     * - Xposed module that modified our classes at install time
     * - Runtime DEX injection
     *
     * @return true if DEX is intact.
     */
    fun verifyDexIntegrity(): Boolean {
        val expectedHash = initialDexHash ?: return true // No baseline yet

        val currentHash = computeDexHash() ?: return true // Can't compute
        val intact = currentHash == expectedHash

        if (!intact) {
            Log.w(TAG, "DEX integrity violation: expected=$expectedHash, got=$currentHash")
        }

        return intact
    }

    /**
     * Check for unexpected library injection.
     *
     * Counts loaded .so libraries in /proc/self/maps and compares
     * against the initial count. A significant increase suggests injection.
     *
     * Note: Some increase is normal (lazy loading). We use a threshold
     * to avoid false positives.
     *
     * @return true if no injection suspected.
     */
    fun verifyLibraryIntegrity(): Boolean {
        val currentCount = countLoadedLibraries()
        val threshold = initialLibraryCount + 5 // Allow 5 new libraries (lazy loading)

        if (currentCount > threshold) {
            Log.w(TAG, "Library count increased: $initialLibraryCount → $currentCount (threshold: $threshold)")
            return false
        }

        return true
    }

    /**
     * Check /proc/self/maps for known injection libraries.
     *
     * @return true if no injection detected.
     */
    fun verifyNoInjection(): Boolean {
        val injectionSignatures = arrayOf(
            "frida",
            "xposed",
            "substrate",
            "libgadget",
            "libhook",
            "libinject",
        )

        try {
            val maps = File("/proc/self/maps").readText()
            val lower = maps.lowercase()

            for (sig in injectionSignatures) {
                if (lower.contains(sig)) {
                    Log.w(TAG, "Injection detected in maps: $sig")
                    return false
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read /proc/self/maps: ${e.message}")
        }

        return true
    }

    /**
     * Run all integrity checks.
     *
     * @return true if all checks pass.
     */
    fun verifyAll(expectedCertHash: String? = null): IntegrityResult {
        return IntegrityResult(
            signatureValid = verifySignature(expectedCertHash),
            dexIntact = verifyDexIntegrity(),
            librariesIntact = verifyLibraryIntegrity(),
            noInjection = verifyNoInjection(),
        )
    }

    data class IntegrityResult(
        val signatureValid: Boolean,
        val dexIntact: Boolean,
        val librariesIntact: Boolean,
        val noInjection: Boolean,
    ) {
        val isIntact: Boolean get() =
            signatureValid && dexIntact && librariesIntact && noInjection

        val failedChecks: String get() {
            val failed = mutableListOf<String>()
            if (!signatureValid) failed.add("signature")
            if (!dexIntact) failed.add("dex")
            if (!librariesIntact) failed.add("libraries")
            if (!noInjection) failed.add("injection")
            return failed.joinToString(",")
        }
    }

    // ─── Internal helpers ───

    /**
     * Compute SHA-256 hash of classes.dex from the APK.
     */
    private fun computeDexHash(): String? {
        try {
            val apkPath = context.applicationInfo.sourceDir
            val zipFile = ZipFile(apkPath)
            val dexEntry = zipFile.getEntry("classes.dex") ?: return null

            val digest = MessageDigest.getInstance("SHA-256")
            zipFile.getInputStream(dexEntry).use { stream ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (stream.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            zipFile.close()

            return digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to compute DEX hash: ${e.message}")
            return null
        }
    }

    /**
     * Count loaded .so libraries from /proc/self/maps.
     */
    private fun countLoadedLibraries(): Int {
        return try {
            File("/proc/self/maps").readLines()
                .count { it.endsWith(".so") || it.contains(".so ") }
        } catch (e: Exception) {
            0
        }
    }
}
