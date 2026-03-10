package com.myapp.cyber_guard

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.util.Log
import java.io.File

/**
 * Emulator and virtual machine detection for Android.
 *
 * ## Why detect emulators:
 * Emulators give the attacker full control over the environment:
 * - They can read framebuffer memory directly
 * - They can intercept all system calls
 * - They can snapshot and replay the entire VM state
 * - FLAG_SECURE is not enforced by emulator compositors
 *
 * ## Detection signals:
 * 1. **Build properties** — FINGERPRINT, MODEL, MANUFACTURER contain emulator strings
 * 2. **Hardware indicators** — goldfish, ranchu, generic hardware
 * 3. **Emulator files** — /dev/qemu_pipe, /dev/goldfish_pipe, init.goldfish.rc
 * 4. **Sensor count** — Emulators have fewer physical sensors
 * 5. **Telephony properties** — Android emulator uses specific operator/phone strings
 *
 * ## False positive avoidance:
 * Some cheap Android devices have generic build properties similar to
 * emulators. We use a scoring system — each signal adds points,
 * and we require a threshold to declare "emulator".
 */
class EmulatorDetector(private val context: Context) {

    companion object {
        private const val TAG = "EmulatorDetector"

        /** Score threshold: 3+ signals = definitely an emulator */
        private const val EMULATOR_THRESHOLD = 3
    }

    data class EmulatorCheckResult(
        val buildPropsScore: Int = 0,
        val hardwareScore: Int = 0,
        val emulatorFilesFound: Boolean = false,
        val lowSensorCount: Boolean = false,
        val suspiciousTelephony: Boolean = false,
    ) {
        val totalScore: Int get() =
            buildPropsScore + hardwareScore +
            (if (emulatorFilesFound) 2 else 0) +
            (if (lowSensorCount) 1 else 0) +
            (if (suspiciousTelephony) 1 else 0)

        val isEmulator: Boolean get() = totalScore >= EMULATOR_THRESHOLD

        val detectionMethods: String get() {
            val methods = mutableListOf<String>()
            if (buildPropsScore > 0) methods.add("build_props:$buildPropsScore")
            if (hardwareScore > 0) methods.add("hardware:$hardwareScore")
            if (emulatorFilesFound) methods.add("emulator_files")
            if (lowSensorCount) methods.add("low_sensors")
            if (suspiciousTelephony) methods.add("telephony")
            return methods.joinToString(",")
        }
    }

    fun detect(): EmulatorCheckResult {
        return EmulatorCheckResult(
            buildPropsScore = checkBuildProperties(),
            hardwareScore = checkHardware(),
            emulatorFilesFound = checkEmulatorFiles(),
            lowSensorCount = checkSensors(),
            suspiciousTelephony = checkTelephony(),
        )
    }

    // ─── Signal 1: Build properties ───

    /**
     * Check Build.* properties for emulator indicators.
     *
     * Each property gets scored independently. Common emulator values:
     * - FINGERPRINT: "generic", "sdk", "google_sdk", "Genymotion"
     * - MODEL: "sdk", "Emulator", "Android SDK"
     * - MANUFACTURER: "Genymotion", "unknown"
     * - PRODUCT: "sdk", "google_sdk", "vbox86p"
     * - BRAND: "generic"
     * - HARDWARE: "goldfish", "ranchu", "vbox86"
     */
    private fun checkBuildProperties(): Int {
        var score = 0

        // FINGERPRINT
        val fingerprint = Build.FINGERPRINT.lowercase()
        if (fingerprint.startsWith("generic") ||
            fingerprint.startsWith("unknown") ||
            fingerprint.contains("sdk") ||
            fingerprint.contains("genymotion") ||
            fingerprint.contains("vbox") ||
            fingerprint.contains("test-keys")
        ) {
            score++
        }

        // MODEL
        val model = Build.MODEL.lowercase()
        if (model.contains("sdk") ||
            model.contains("emulator") ||
            model.contains("android sdk") ||
            model == "google_sdk"
        ) {
            score++
        }

        // MANUFACTURER
        val manufacturer = Build.MANUFACTURER.lowercase()
        if (manufacturer.contains("genymotion") ||
            manufacturer.contains("unknown") ||
            manufacturer.contains("nox") ||
            manufacturer.contains("bluestacks")
        ) {
            score++
        }

        // PRODUCT
        val product = Build.PRODUCT.lowercase()
        if (product.contains("sdk") ||
            product.contains("vbox") ||
            product.contains("google_sdk") ||
            product.contains("nox") ||
            product == "full_x86" ||
            product == "full_x86_64"
        ) {
            score++
        }

        // BOARD
        val board = Build.BOARD.lowercase()
        if (board == "unknown" ||
            board.contains("goldfish") ||
            board.contains("nox")
        ) {
            score++
        }

        if (score > 0) {
            Log.w(TAG, "Build property score: $score (FP=$fingerprint, MODEL=$model, MFR=$manufacturer)")
        }

        return score
    }

    // ─── Signal 2: Hardware indicators ───

    /**
     * Check hardware identifiers for emulator-specific values.
     */
    private fun checkHardware(): Int {
        var score = 0

        val hardware = Build.HARDWARE.lowercase()
        if (hardware.contains("goldfish") ||
            hardware.contains("ranchu") ||
            hardware.contains("vbox86") ||
            hardware.contains("nox")
        ) {
            score += 2 // Strong signal
        }

        // BOOTLOADER
        val bootloader = Build.BOOTLOADER.lowercase()
        if (bootloader == "unknown" || bootloader.contains("nox")) {
            score++
        }

        if (score > 0) {
            Log.w(TAG, "Hardware score: $score (HW=$hardware, BL=$bootloader)")
        }

        return score
    }

    // ─── Signal 3: Emulator-specific files ───

    /**
     * Check for files that only exist on emulators.
     *
     * QEMU-based emulators (Android Studio emulator, Genymotion) create
     * specific device files and init scripts.
     */
    private fun checkEmulatorFiles(): Boolean {
        val emulatorFiles = arrayOf(
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/dev/socket/qemud",
            "/dev/qemu_trace",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/genyd",           // Genymotion
            "/dev/socket/baseband_genyd",  // Genymotion
            "/system/bin/nox",             // NOX Player
            "/system/bin/nox-prop",        // NOX Player
            "/system/lib/vboxguest.ko",    // VirtualBox
        )

        return emulatorFiles.any { File(it).exists() }.also { found ->
            if (found) Log.w(TAG, "Emulator files detected")
        }
    }

    // ─── Signal 4: Sensor count ───

    /**
     * Check physical sensor availability.
     *
     * Real devices have 10-30+ sensors (accelerometer, gyroscope, magnetometer,
     * proximity, light, pressure, etc.). Emulators typically simulate only
     * 0-5 sensors. A very low sensor count is suspicious.
     */
    private fun checkSensors(): Boolean {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
            ?: return false

        val sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)
        val hasAccelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
        val hasGyroscope = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null

        // Very few sensors AND missing basic sensors = likely emulator
        val isSuspicious = sensors.size < 4 && !hasAccelerometer && !hasGyroscope
        if (isSuspicious) {
            Log.w(TAG, "Low sensor count: ${sensors.size} (no accel/gyro)")
        }

        return isSuspicious
    }

    // ─── Signal 5: Telephony properties ───

    /**
     * Check for emulator-specific telephony values.
     *
     * The Android emulator uses specific default values for phone number,
     * operator name, and IMEI. These are weak signals because some cheap
     * devices also have generic telephony values.
     */
    private fun checkTelephony(): Boolean {
        try {
            // Check system properties via reflection-free Build fields
            val serial = Build.SERIAL ?: ""
            if (serial.equals("unknown", ignoreCase = true) ||
                serial.equals("android", ignoreCase = true)
            ) {
                Log.w(TAG, "Suspicious serial: $serial")
                return true
            }

            // Check for well-known emulator device names
            val device = Build.DEVICE.lowercase()
            if (device.startsWith("generic") ||
                device.contains("emu") ||
                device.contains("x86")
            ) {
                Log.w(TAG, "Suspicious device name: $device")
                return true
            }
        } catch (_: Exception) {
            // Security exception or permission denied — not suspicious
        }

        return false
    }
}
