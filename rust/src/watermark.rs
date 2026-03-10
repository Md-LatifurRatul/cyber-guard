//! Steganographic Watermark Engine
//!
//! ## How LSB Steganography Works:
//!
//! Each pixel in an RGBA image has 4 channels: Red, Green, Blue, Alpha.
//! Each channel is 8 bits (0-255). The Least Significant Bit (LSB) of each
//! channel contributes the smallest visual difference — changing it alters
//! the color by at most 1/256, which is imperceptible to the human eye.
//!
//! We encode binary data by replacing the LSB of each color channel:
//!
//! ```text
//! Original pixel:  R=10110100  G=11001010  B=01110011  A=11111111
//! Data bits:          ↓1          ↓0          ↓1          ↓1
//! Modified pixel:  R=10110101  G=11001010  B=01110011  A=11111111
//!                        ^LSB       ^same       ^same       ^untouched
//! ```
//!
//! We use 3 bits per pixel (R, G, B channels only — Alpha stays untouched
//! to avoid transparency artifacts).
//!
//! ## Watermark Payload (56 bytes total):
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ Magic (4B) │ UserID (32B) │ Timestamp (8B) │ Session (12B) │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! - **Magic bytes** (4B): `0xCG01` — identifies this as a CyberGuard watermark
//! - **User ID** (32B): SHA-256 hash of user's email/identifier
//! - **Timestamp** (8B): Unix timestamp in milliseconds (u64 big-endian)
//! - **Session ID** (12B): Random session identifier
//!
//! ## Minimum Image Size:
//!
//! 56 bytes = 448 bits. At 3 bits per pixel, we need ceil(448/3) = 150 pixels minimum.
//! A 13x12 image (156 pixels) is sufficient. Any real content image will work.

/// Magic bytes to identify CyberGuard watermarks ("CG01" in ASCII).
const WATERMARK_MAGIC: [u8; 4] = [0x43, 0x47, 0x30, 0x31];

/// Total watermark payload size in bytes.
const PAYLOAD_SIZE: usize = 56;

/// Bits used per pixel (R, G, B — not Alpha).
const BITS_PER_PIXEL: usize = 3;

/// Minimum number of pixels needed to encode a full watermark.
const MIN_PIXELS: usize = (PAYLOAD_SIZE * 8 + BITS_PER_PIXEL - 1) / BITS_PER_PIXEL;

/// Error codes returned by watermark functions.
#[repr(i32)]
pub enum WatermarkError {
    Success = 0,
    ImageTooSmall = -1,
    InvalidPayload = -2,
    MagicMismatch = -3,
    BufferTooSmall = -4,
}

/// Encode a watermark into RGBA pixel data.
///
/// # Arguments
/// * `pixels` - Mutable RGBA pixel buffer (4 bytes per pixel)
/// * `pixel_count` - Number of pixels in the buffer
/// * `user_id` - 32-byte user identifier (SHA-256 hash of email)
/// * `timestamp_ms` - Unix timestamp in milliseconds
/// * `session_id` - 12-byte session identifier
///
/// # Returns
/// `WatermarkError::Success` (0) on success, negative error code on failure.
///
/// # How encoding works:
/// 1. Assemble the 56-byte payload: magic + user_id + timestamp + session
/// 2. Convert payload to a bit stream (448 bits)
/// 3. For each bit, replace the LSB of the corresponding color channel
///    - Pixel N's Red channel gets bit N*3
///    - Pixel N's Green channel gets bit N*3+1
///    - Pixel N's Blue channel gets bit N*3+2
///    - Alpha channel is never modified
pub fn encode_watermark(
    pixels: &mut [u8],
    user_id: &[u8; 32],
    timestamp_ms: u64,
    session_id: &[u8; 12],
) -> i32 {
    let pixel_count = pixels.len() / 4;
    if pixel_count < MIN_PIXELS {
        return WatermarkError::ImageTooSmall as i32;
    }

    // Assemble payload
    let payload = build_payload(user_id, timestamp_ms, session_id);

    // Encode payload bits into pixel LSBs
    let mut bit_index = 0;
    let total_bits = PAYLOAD_SIZE * 8;

    for pixel_idx in 0..pixel_count {
        if bit_index >= total_bits {
            break;
        }

        let base = pixel_idx * 4; // RGBA offset — safe because pixels.len() == pixel_count * 4

        // Encode into R, G, B channels (skip Alpha at base+3)
        for channel in 0..3 {
            if bit_index >= total_bits {
                break;
            }
            let bit = get_bit(&payload, bit_index);
            pixels[base + channel] = set_lsb(pixels[base + channel], bit);
            bit_index += 1;
        }
    }

    WatermarkError::Success as i32
}

/// Decode a watermark from RGBA pixel data.
///
/// # Arguments
/// * `pixels` - RGBA pixel buffer (4 bytes per pixel)
/// * `pixel_count` - Number of pixels
/// * `user_id_out` - Output buffer for 32-byte user ID
/// * `timestamp_ms_out` - Output for timestamp
/// * `session_id_out` - Output buffer for 12-byte session ID
///
/// # Returns
/// `WatermarkError::Success` (0) on success, negative error code on failure.
///
/// # How decoding works:
/// 1. Read LSBs from R, G, B channels of each pixel
/// 2. Reassemble into the 56-byte payload
/// 3. Verify magic bytes match
/// 4. Extract user_id, timestamp, session_id
pub fn decode_watermark(
    pixels: &[u8],
    user_id_out: &mut [u8; 32],
    timestamp_ms_out: &mut u64,
    session_id_out: &mut [u8; 12],
) -> i32 {
    let pixel_count = pixels.len() / 4;
    if pixel_count < MIN_PIXELS {
        return WatermarkError::ImageTooSmall as i32;
    }

    // Extract payload bits from pixel LSBs
    let mut payload = [0u8; PAYLOAD_SIZE];
    let mut bit_index = 0;
    let total_bits = PAYLOAD_SIZE * 8;

    for pixel_idx in 0..pixel_count {
        if bit_index >= total_bits {
            break;
        }

        let base = pixel_idx * 4;

        // Read from R, G, B channels
        for channel in 0..3 {
            if bit_index >= total_bits {
                break;
            }
            let bit = pixels[base + channel] & 1;
            set_bit(&mut payload, bit_index, bit);
            bit_index += 1;
        }
    }

    // Verify magic bytes
    if payload[0..4] != WATERMARK_MAGIC {
        return WatermarkError::MagicMismatch as i32;
    }

    // Extract fields
    user_id_out.copy_from_slice(&payload[4..36]);
    *timestamp_ms_out = u64::from_be_bytes(payload[36..44].try_into().unwrap());
    session_id_out.copy_from_slice(&payload[44..56]);

    WatermarkError::Success as i32
}

// --- Internal helpers ---

/// Build the 56-byte payload from components.
fn build_payload(user_id: &[u8; 32], timestamp_ms: u64, session_id: &[u8; 12]) -> [u8; PAYLOAD_SIZE] {
    let mut payload = [0u8; PAYLOAD_SIZE];

    // Magic (4 bytes)
    payload[0..4].copy_from_slice(&WATERMARK_MAGIC);
    // User ID (32 bytes)
    payload[4..36].copy_from_slice(user_id);
    // Timestamp (8 bytes, big-endian)
    payload[36..44].copy_from_slice(&timestamp_ms.to_be_bytes());
    // Session ID (12 bytes)
    payload[44..56].copy_from_slice(session_id);

    payload
}

/// Get a single bit from a byte array at the given bit index.
#[inline(always)]
fn get_bit(data: &[u8], bit_index: usize) -> u8 {
    let byte_idx = bit_index / 8;
    let bit_offset = 7 - (bit_index % 8); // MSB first
    (data[byte_idx] >> bit_offset) & 1
}

/// Set a single bit in a byte array at the given bit index.
#[inline(always)]
fn set_bit(data: &mut [u8], bit_index: usize, value: u8) {
    let byte_idx = bit_index / 8;
    let bit_offset = 7 - (bit_index % 8);
    if value == 1 {
        data[byte_idx] |= 1 << bit_offset;
    } else {
        data[byte_idx] &= !(1 << bit_offset);
    }
}

/// Set the LSB of a byte to the given bit value.
#[inline(always)]
fn set_lsb(byte: u8, bit: u8) -> u8 {
    (byte & 0xFE) | (bit & 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        // Create a test image (200 pixels, 800 bytes RGBA)
        let mut pixels = vec![128u8; 800];

        let user_id: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let timestamp_ms: u64 = 1700000000000;
        let session_id: [u8; 12] = [0xAA; 12];

        // Encode
        let result = encode_watermark(&mut pixels, &user_id, timestamp_ms, &session_id);
        assert_eq!(result, 0);

        // Decode
        let mut decoded_user_id = [0u8; 32];
        let mut decoded_timestamp: u64 = 0;
        let mut decoded_session = [0u8; 12];

        let result = decode_watermark(
            &pixels,
            &mut decoded_user_id,
            &mut decoded_timestamp,
            &mut decoded_session,
        );
        assert_eq!(result, 0);

        // Verify
        assert_eq!(decoded_user_id, user_id);
        assert_eq!(decoded_timestamp, timestamp_ms);
        assert_eq!(decoded_session, session_id);
    }

    #[test]
    fn test_image_too_small() {
        let mut pixels = vec![0u8; 100]; // 25 pixels, way too small
        let user_id = [0u8; 32];
        let session_id = [0u8; 12];

        let result = encode_watermark(&mut pixels, &user_id, 0, &session_id);
        assert_eq!(result, WatermarkError::ImageTooSmall as i32);
    }

    #[test]
    fn test_magic_mismatch() {
        // Create pixels with no watermark (random data)
        let pixels = vec![0u8; 800];
        let mut user_id = [0u8; 32];
        let mut timestamp: u64 = 0;
        let mut session_id = [0u8; 12];

        let result = decode_watermark(&pixels, &mut user_id, &mut timestamp, &mut session_id);
        assert_eq!(result, WatermarkError::MagicMismatch as i32);
    }

    #[test]
    fn test_lsb_modification_is_minimal() {
        let mut pixels = vec![200u8; 800];
        let original = pixels.clone();
        let user_id = [0xFFu8; 32];
        let session_id = [0xFFu8; 12];

        encode_watermark(&mut pixels, &user_id, u64::MAX, &session_id);

        // Each modified pixel should differ by at most 1 per channel
        for i in 0..pixels.len() {
            let diff = (pixels[i] as i16 - original[i] as i16).unsigned_abs();
            assert!(diff <= 1, "Pixel byte {} changed by {} (too much)", i, diff);
        }
    }

    #[test]
    fn test_alpha_channel_untouched() {
        let mut pixels = vec![0u8; 800];
        // Set all alpha channels to a known value
        for i in (3..800).step_by(4) {
            pixels[i] = 0xFE;
        }
        let original_alphas: Vec<u8> = (3..800).step_by(4).map(|i| pixels[i]).collect();

        let user_id = [0xABu8; 32];
        let session_id = [0xCDu8; 12];
        encode_watermark(&mut pixels, &user_id, 12345, &session_id);

        // All alpha channels should be unchanged
        let new_alphas: Vec<u8> = (3..800).step_by(4).map(|i| pixels[i]).collect();
        assert_eq!(original_alphas, new_alphas, "Alpha channels were modified!");
    }
}
