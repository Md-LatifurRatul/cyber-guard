#!/bin/bash
# CyberGuard Rust Core — Cross-Platform Build Script
#
# Builds the Rust core library for all supported platforms:
# - macOS (arm64, x86_64) → .dylib for development, .a for production
# - iOS (arm64, arm64-sim, x86_64-sim) → .a (static library)
# - Android (arm64, armv7, x86_64, x86) → .so (shared library)
#
# Usage:
#   ./build_all.sh            # Build all platforms
#   ./build_all.sh macos      # Build macOS only
#   ./build_all.sh ios        # Build iOS only
#   ./build_all.sh android    # Build Android only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$SCRIPT_DIR"

cd "$RUST_DIR"

# Regenerate C header if cbindgen is available
if command -v cbindgen &> /dev/null; then
    cbindgen --config cbindgen.toml --crate cyberguard_core --output include/cyberguard_core.h 2>/dev/null
    # Fix ENCRYPTION_OVERHEAD define (cbindgen can't resolve internal constants)
    sed -i '' 's/#define ENCRYPTION_OVERHEAD.*/#define ENCRYPTION_OVERHEAD 28/' include/cyberguard_core.h 2>/dev/null || true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[CyberGuard]${NC} $1"; }
warn() { echo -e "${YELLOW}[CyberGuard]${NC} $1"; }
error() { echo -e "${RED}[CyberGuard]${NC} $1"; }

# ============================================================================
# macOS Build
# ============================================================================
build_macos() {
    log "Building macOS (arm64 + x86_64)..."

    cargo build --release --target aarch64-apple-darwin
    cargo build --release --target x86_64-apple-darwin

    # Create universal binary (fat library)
    mkdir -p "$PROJECT_ROOT/macos/Runner/Libraries"

    lipo -create \
        target/aarch64-apple-darwin/release/libcyberguard_core.dylib \
        target/x86_64-apple-darwin/release/libcyberguard_core.dylib \
        -output "$PROJECT_ROOT/macos/Runner/Libraries/libcyberguard_core.dylib"

    # Also create static library for linking
    lipo -create \
        target/aarch64-apple-darwin/release/libcyberguard_core.a \
        target/x86_64-apple-darwin/release/libcyberguard_core.a \
        -output "$PROJECT_ROOT/macos/Runner/Libraries/libcyberguard_core.a"

    # Copy C header
    cp include/cyberguard_core.h "$PROJECT_ROOT/macos/Runner/Libraries/"

    log "macOS build complete → macos/Runner/Libraries/"
}

# ============================================================================
# iOS Build
# ============================================================================
build_ios() {
    log "Building iOS (arm64 device + arm64-sim + x86_64-sim)..."

    cargo build --release --target aarch64-apple-ios
    cargo build --release --target aarch64-apple-ios-sim
    cargo build --release --target x86_64-apple-ios

    mkdir -p "$PROJECT_ROOT/ios/Runner/Libraries"

    # Device: single arch static library
    cp target/aarch64-apple-ios/release/libcyberguard_core.a \
       "$PROJECT_ROOT/ios/Runner/Libraries/libcyberguard_core_device.a"

    # Simulator: universal binary (arm64 + x86_64)
    lipo -create \
        target/aarch64-apple-ios-sim/release/libcyberguard_core.a \
        target/x86_64-apple-ios/release/libcyberguard_core.a \
        -output "$PROJECT_ROOT/ios/Runner/Libraries/libcyberguard_core_sim.a"

    # Create XCFramework for Xcode (handles device + simulator automatically)
    rm -rf "$PROJECT_ROOT/ios/Runner/Libraries/CyberGuardCore.xcframework"
    xcodebuild -create-xcframework \
        -library "$PROJECT_ROOT/ios/Runner/Libraries/libcyberguard_core_device.a" \
        -headers include/ \
        -library "$PROJECT_ROOT/ios/Runner/Libraries/libcyberguard_core_sim.a" \
        -headers include/ \
        -output "$PROJECT_ROOT/ios/Runner/Libraries/CyberGuardCore.xcframework"

    # Copy C header
    cp include/cyberguard_core.h "$PROJECT_ROOT/ios/Runner/Libraries/"

    log "iOS build complete → ios/Runner/Libraries/"
}

# ============================================================================
# Android Build
# ============================================================================
build_android() {
    log "Building Android (arm64, armv7, x86_64, x86)..."

    # Check for NDK
    NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk}"
    if [ ! -d "$NDK_HOME" ]; then
        # Try to find NDK in SDK
        NDK_HOME=$(find "$HOME/Library/Android/sdk/ndk" -maxdepth 1 -type d | sort -V | tail -1 2>/dev/null || true)
    fi

    if [ -z "$NDK_HOME" ] || [ ! -d "$NDK_HOME" ]; then
        error "Android NDK not found. Set ANDROID_NDK_HOME or install NDK via Android Studio."
        return 1
    fi

    # Check for cargo-ndk
    if ! command -v cargo-ndk &> /dev/null; then
        warn "Installing cargo-ndk..."
        cargo install cargo-ndk
    fi

    # Build for each Android architecture
    cargo ndk \
        --target aarch64-linux-android \
        --target armv7-linux-androideabi \
        --target x86_64-linux-android \
        --target i686-linux-android \
        --platform 24 \
        --output-dir "$PROJECT_ROOT/android/app/src/main/jniLibs" \
        build --release

    log "Android build complete → android/app/src/main/jniLibs/"
}

# ============================================================================
# Main
# ============================================================================
TARGET="${1:-all}"

case "$TARGET" in
    macos)
        build_macos
        ;;
    ios)
        build_ios
        ;;
    android)
        build_android
        ;;
    all)
        build_macos
        build_ios
        build_android
        ;;
    *)
        error "Unknown target: $TARGET"
        echo "Usage: $0 [macos|ios|android|all]"
        exit 1
        ;;
esac

log "Build complete!"
