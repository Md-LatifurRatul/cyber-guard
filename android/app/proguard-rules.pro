# ═══════════════════════════════════════════════════════════════════════════════
# CyberGuard ProGuard/R8 Rules
# ═══════════════════════════════════════════════════════════════════════════════
#
# R8 is Android's code shrinker and obfuscator. It:
#   1. Removes unused code (tree shaking)
#   2. Renames classes/methods/fields (obfuscation)
#   3. Optimizes bytecode (inlining, constant folding)
#
# WHY THIS MATTERS FOR SECURITY:
# Obfuscated code makes reverse engineering significantly harder.
# Instead of seeing "RootDetector.checkMagisk()", an attacker sees "a.b.c()".
# Combined with our C++ native code (which is already compiled to machine code),
# this creates a substantial barrier to static analysis.
#
# WHAT WE MUST KEEP:
# - JNI method names (C++ calls Kotlin by exact name via JNI)
# - Flutter plugin registration (engine finds plugin by class name)
# - MethodChannel handler methods (called by string name from Dart)
#
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Flutter Framework ───
# Flutter engine uses reflection to find the plugin registrant.
-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }

# ─── CyberGuard Plugin Entry Point ───
# The Flutter engine locates this class by name during plugin registration.
# If R8 renames it, the plugin fails to load silently.
-keep class com.myapp.cyber_guard.CyberGuardPlugin {
    public static void registerWith(io.flutter.plugin.common.PluginRegistry$Registrar);
    public void onAttachedToEngine(io.flutter.embedding.engine.plugins.FlutterPlugin$FlutterPluginBinding);
    public void onDetachedFromEngine(io.flutter.embedding.engine.plugins.FlutterPlugin$FlutterPluginBinding);
}

# ─── JNI Bridge ───
# C++ native code calls these methods via JNI using exact signatures.
# If R8 renames them, JNI lookups fail with NoSuchMethodError.
#
# SecurityBridge.kt: All native method declarations
-keep class com.myapp.cyber_guard.SecurityBridge {
    native <methods>;
    # JNI callback methods (called FROM C++ TO Kotlin)
    public void onSecurityEvent(java.lang.String, java.lang.String, long, java.lang.String);
}

# ─── Security Detectors ───
# These classes are accessed via reflection in some code paths (e.g., when
# SecurityMonitor creates detector instances). Keep class names + public API.
-keep class com.myapp.cyber_guard.RootDetector { public *; }
-keep class com.myapp.cyber_guard.EmulatorDetector { public *; }
-keep class com.myapp.cyber_guard.MemoryProtection { public *; }
-keep class com.myapp.cyber_guard.ScreenCaptureDetector { public *; }
-keep class com.myapp.cyber_guard.SecurityMonitor { public *; }

# ─── Native Library Loading ───
# System.loadLibrary() and DynamicLibrary.open() use string names.
# Keep the library loading code path intact.
-keepclassmembers class * {
    native <methods>;
}

# ─── Enum Values ───
# Enums are serialized by name in some MethodChannel payloads.
# R8 can rename enum constants, breaking deserialization.
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ─── Kotlin Metadata ───
# Keep Kotlin metadata for coroutines and reflection.
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**

# ─── Crypto / Security APIs ───
# Ensure Android KeyStore and security provider classes aren't stripped.
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keep class android.security.keystore.** { *; }

# ─── Aggressive Obfuscation for Security Classes ───
# Allow R8 to aggressively obfuscate everything NOT in the keep rules above.
# This maximizes obfuscation of our detection logic.
-repackageclasses 'cg'
-allowaccessmodification

# ─── Remove Logging in Release ───
# Strip all debugPrint / Log.d calls from release builds.
# Prevents attackers from reading detection logic via logcat.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
    public static int i(...);
}

# ─── Stack Traces ───
# Keep source file and line numbers for crash reports (but not method names).
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
