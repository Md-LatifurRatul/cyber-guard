plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.myapp.cyber_guard"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "com.myapp.cyber_guard"
        minSdk = 24  // Android 7.0 — required for DisplayManager APIs
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // NDK/CMake configuration for C++ native security code
        externalNativeBuild {
            cmake {
                // -O2: Optimize for speed (security checks must be fast)
                // -fvisibility=hidden: Hide internal symbols from reverse engineers
                cppFlags += listOf("-O2", "-fvisibility=hidden", "-fvisibility-inlines-hidden")
                // Use static C++ runtime to avoid dependency on device's libc++
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }

        // Build for all common architectures
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
    }

    // Point to our CMakeLists.txt for native C++ compilation
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            signingConfig = signingConfigs.getByName("debug")

            // R8 obfuscation — critical for security.
            // Renames classes/methods to prevent reverse engineering.
            // Without this, an attacker can read "RootDetector.checkMagisk()"
            // in the APK and understand exactly what we're checking.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

dependencies {
    // AndroidX Media3 ExoPlayer — Google's official media playback library.
    // NOT a security dependency — purely media decoding and rendering.
    // Supports: MP4, WebM, MKV, MOV, 3GP, HLS, DASH, RTMP, SmoothStreaming.
    implementation("androidx.media3:media3-exoplayer:1.5.1")
    implementation("androidx.media3:media3-exoplayer-hls:1.5.1")
    implementation("androidx.media3:media3-exoplayer-dash:1.5.1")
}

flutter {
    source = "../.."
}
