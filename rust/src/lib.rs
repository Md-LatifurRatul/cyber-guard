//! CyberGuard Core — FFI Exports
//!
//! ## FFI Safety Rules:
//!
//! 1. **Never panic across FFI boundary** — Rust panics that cross into
//!    C/Dart cause undefined behavior. Every function uses `catch_unwind`
//!    to convert panics into error codes.
//!
//! 2. **All pointers validated** — Null pointer checks before dereferencing.
//!    Invalid pointers would crash the entire app.
//!
//! 3. **No heap allocation returned** — We write into caller-provided buffers.
//!    This avoids memory management issues between Rust and Dart allocators.
//!    Exception: `cg_free_string` for strings allocated by Rust.
//!
//! 4. **C-compatible types only** — No Rust-specific types cross the boundary.
//!    Only `i32`, `u64`, `*const u8`, `*mut u8`, etc.
//!
//! ## Naming convention:
//! All exported functions start with `cg_` (CyberGuard) to avoid symbol
//! conflicts with other native libraries.

mod crypto;
mod detection;
mod watermark;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic;
use std::slice;

// ============================================================================
// WATERMARK FFI EXPORTS
// ============================================================================

/// Encode a steganographic watermark into RGBA pixel data.
///
/// # Safety
/// - `pixels` must point to a valid buffer of at least `pixel_count * 4` bytes
/// - `user_id` must point to exactly 32 bytes
/// - `session_id` must point to exactly 12 bytes
#[no_mangle]
pub unsafe extern "C" fn cg_watermark_encode(
    pixels: *mut u8,
    pixel_count: u32,
    user_id: *const u8,
    timestamp_ms: u64,
    session_id: *const u8,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if pixels.is_null() || user_id.is_null() || session_id.is_null() {
            return watermark::WatermarkError::InvalidPayload as i32;
        }

        let byte_count = match (pixel_count as usize).checked_mul(4) {
            Some(n) => n,
            None => return watermark::WatermarkError::ImageTooSmall as i32,
        };

        let pixel_buf = slice::from_raw_parts_mut(pixels, byte_count);
        let uid = &*(user_id as *const [u8; 32]);
        let sid = &*(session_id as *const [u8; 12]);

        watermark::encode_watermark(pixel_buf, uid, timestamp_ms, sid)
    });

    result.unwrap_or(-99) // -99 = internal panic
}

/// Decode a steganographic watermark from RGBA pixel data.
///
/// # Safety
/// - `pixels` must point to a valid buffer of at least `pixel_count * 4` bytes
/// - `user_id_out` must point to a writable buffer of at least 32 bytes
/// - `timestamp_ms_out` must point to a valid u64
/// - `session_id_out` must point to a writable buffer of at least 12 bytes
#[no_mangle]
pub unsafe extern "C" fn cg_watermark_decode(
    pixels: *const u8,
    pixel_count: u32,
    user_id_out: *mut u8,
    timestamp_ms_out: *mut u64,
    session_id_out: *mut u8,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if pixels.is_null()
            || user_id_out.is_null()
            || timestamp_ms_out.is_null()
            || session_id_out.is_null()
        {
            return watermark::WatermarkError::InvalidPayload as i32;
        }

        let byte_count = match (pixel_count as usize).checked_mul(4) {
            Some(n) => n,
            None => return watermark::WatermarkError::ImageTooSmall as i32,
        };

        let pixel_buf = slice::from_raw_parts(pixels, byte_count);
        let uid_out = &mut *(user_id_out as *mut [u8; 32]);
        let sid_out = &mut *(session_id_out as *mut [u8; 12]);

        watermark::decode_watermark(pixel_buf, uid_out, &mut *timestamp_ms_out, sid_out)
    });

    result.unwrap_or(-99)
}

/// Get the minimum number of pixels required for watermark encoding.
#[no_mangle]
pub extern "C" fn cg_watermark_min_pixels() -> u32 {
    150 // ceil(56 * 8 / 3)
}

// ============================================================================
// CRYPTO FFI EXPORTS
// ============================================================================

/// Encrypt data using AES-256-GCM.
///
/// # Safety
/// - `key` must point to exactly 32 bytes
/// - `plaintext` must point to `plaintext_len` bytes
/// - `output` must point to a writable buffer of at least `plaintext_len + 28` bytes
///
/// # Returns
/// Number of bytes written to output (positive), or negative error code.
#[no_mangle]
pub unsafe extern "C" fn cg_encrypt(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: u32,
    output: *mut u8,
    output_capacity: u32,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if key.is_null() || plaintext.is_null() || output.is_null() {
            return crypto::CryptoError::EncryptionFailed as i32;
        }

        let key_arr = &*(key as *const [u8; 32]);
        let pt = slice::from_raw_parts(plaintext, plaintext_len as usize);
        let out = slice::from_raw_parts_mut(output, output_capacity as usize);

        crypto::encrypt(key_arr, pt, out)
    });

    result.unwrap_or(-99)
}

/// Decrypt data using AES-256-GCM.
///
/// # Safety
/// - `key` must point to exactly 32 bytes
/// - `encrypted` must point to `encrypted_len` bytes
/// - `output` must point to a writable buffer of at least `encrypted_len - 28` bytes
///
/// # Returns
/// Number of plaintext bytes written (positive), or negative error code.
#[no_mangle]
pub unsafe extern "C" fn cg_decrypt(
    key: *const u8,
    encrypted: *const u8,
    encrypted_len: u32,
    output: *mut u8,
    output_capacity: u32,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if key.is_null() || encrypted.is_null() || output.is_null() {
            return crypto::CryptoError::DecryptionFailed as i32;
        }

        let key_arr = &*(key as *const [u8; 32]);
        let enc = slice::from_raw_parts(encrypted, encrypted_len as usize);
        let out = slice::from_raw_parts_mut(output, output_capacity as usize);

        crypto::decrypt(key_arr, enc, out)
    });

    result.unwrap_or(-99)
}

/// Generate a cryptographically secure random 256-bit key.
///
/// # Safety
/// - `key_out` must point to a writable buffer of exactly 32 bytes
#[no_mangle]
pub unsafe extern "C" fn cg_generate_key(key_out: *mut u8) -> i32 {
    let result = panic::catch_unwind(|| {
        if key_out.is_null() {
            return crypto::CryptoError::InvalidKeyLength as i32;
        }

        let key = &mut *(key_out as *mut [u8; 32]);
        crypto::generate_key(key);

        crypto::CryptoError::Success as i32
    });

    result.unwrap_or(-99)
}

/// Get the encryption overhead in bytes (nonce + auth tag).
#[no_mangle]
pub extern "C" fn cg_encryption_overhead() -> u32 {
    crypto::ENCRYPTION_OVERHEAD as u32
}

// ============================================================================
// DETECTION FFI EXPORTS
// ============================================================================

/// Check if a process name matches a known screen capture tool.
///
/// # Safety
/// - `process_name` must be a valid null-terminated C string
///
/// # Returns
/// 1 if the process is a known capture tool, 0 if not.
#[no_mangle]
pub unsafe extern "C" fn cg_is_capture_process(process_name: *const c_char) -> i32 {
    let result = panic::catch_unwind(|| {
        if process_name.is_null() {
            return 0;
        }

        let name = match CStr::from_ptr(process_name).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        if detection::is_capture_process(name) { 1 } else { 0 }
    });

    result.unwrap_or(0)
}

/// Check if a string contains hooking framework signatures.
///
/// # Safety
/// - `target` must be a valid null-terminated C string
///
/// # Returns
/// 1 if a hook signature is found, 0 if not.
#[no_mangle]
pub unsafe extern "C" fn cg_is_hook_signature(target: *const c_char) -> i32 {
    let result = panic::catch_unwind(|| {
        if target.is_null() {
            return 0;
        }

        let s = match CStr::from_ptr(target).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        };

        if detection::is_hook_signature(s) { 1 } else { 0 }
    });

    result.unwrap_or(0)
}

/// Compute a FNV-1a checksum over a memory region.
///
/// # Safety
/// - `data` must point to at least `len` bytes
#[no_mangle]
pub unsafe extern "C" fn cg_compute_checksum(data: *const u8, len: u32) -> u64 {
    let result = panic::catch_unwind(|| {
        if data.is_null() || len == 0 {
            return 0u64;
        }

        let buf = slice::from_raw_parts(data, len as usize);
        detection::compute_checksum(buf)
    });

    result.unwrap_or(0)
}

/// Verify a memory region's checksum.
///
/// # Safety
/// - `data` must point to at least `len` bytes
///
/// # Returns
/// 1 if checksum matches (integrity OK), 0 if mismatch (tampered).
#[no_mangle]
pub unsafe extern "C" fn cg_verify_checksum(data: *const u8, len: u32, expected: u64) -> i32 {
    let result = panic::catch_unwind(|| {
        if data.is_null() || len == 0 {
            return 0;
        }

        let buf = slice::from_raw_parts(data, len as usize);
        if detection::verify_checksum(buf, expected) { 1 } else { 0 }
    });

    result.unwrap_or(0)
}

// ============================================================================
// UTILITY FFI EXPORTS
// ============================================================================

/// Free a string allocated by Rust.
///
/// # Safety
/// - `ptr` must be a string previously returned by a `cg_*` function,
///   or null (which is a no-op).
#[no_mangle]
pub unsafe extern "C" fn cg_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Get the library version string.
///
/// # Returns
/// A null-terminated string. Caller must NOT free this pointer
/// (it points to a static string).
#[no_mangle]
pub extern "C" fn cg_version() -> *const c_char {
    // Static ensures the pointer is valid for the entire program lifetime
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}
