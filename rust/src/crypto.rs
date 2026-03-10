//! AES-256-GCM Authenticated Encryption Module
//!
//! ## Why AES-256-GCM:
//!
//! AES-256-GCM provides both **confidentiality** (data is encrypted) and
//! **authenticity** (data hasn't been tampered with). It's the gold standard
//! for symmetric encryption, used by TLS 1.3, Signal Protocol, and most
//! secure communication systems.
//!
//! ## How AES-256-GCM works:
//!
//! ```text
//! ┌─────────┐     ┌─────────────────────────────────────────────┐
//! │ 256-bit │     │              Plaintext                      │
//! │   Key   │     └─────────────────────────────────────────────┘
//! └────┬────┘                       │
//!      │         ┌──────────┐       │
//!      ├────────►│ AES-256  │◄──────┘
//!      │         │   GCM    │
//!      │         └────┬─────┘
//!      │              │
//!      │    ┌─────────┴────────────────────────────────┐
//!      │    │  Nonce(12B) │ Ciphertext │ Auth Tag(16B)  │
//!      │    └──────────────────────────────────────────┘
//! ```
//!
//! - **Key**: 256-bit (32 bytes) secret key
//! - **Nonce**: 96-bit (12 bytes) unique per encryption (NEVER reuse!)
//! - **Auth Tag**: 128-bit (16 bytes) MAC that verifies integrity
//!
//! ## Output format:
//! `[nonce (12 bytes)] [ciphertext] [tag (16 bytes)]`
//!
//! The nonce is prepended to the ciphertext so decryption doesn't need
//! it passed separately.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key, Nonce,
};

/// Nonce size for AES-256-GCM (96 bits).
const NONCE_SIZE: usize = 12;

/// Authentication tag size (128 bits).
const TAG_SIZE: usize = 16;

/// Overhead added by encryption: nonce + tag.
pub const ENCRYPTION_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

/// Error codes for crypto operations.
#[repr(i32)]
pub enum CryptoError {
    Success = 0,
    InvalidKeyLength = -10,
    EncryptionFailed = -11,
    DecryptionFailed = -12,
    BufferTooSmall = -13,
}

/// Encrypt data using AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `output` - Output buffer (must be at least plaintext.len() + ENCRYPTION_OVERHEAD)
///
/// # Returns
/// Number of bytes written to output on success, negative error code on failure.
///
/// # Output format
/// `[nonce (12B)] [ciphertext (same len as plaintext)] [auth tag (16B)]`
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], output: &mut [u8]) -> i32 {
    let required_size = plaintext.len() + ENCRYPTION_OVERHEAD;
    if output.len() < required_size {
        return CryptoError::BufferTooSmall as i32;
    }

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Generate random nonce (MUST be unique per encryption with same key)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt (ciphertext includes appended tag)
    let ciphertext_with_tag = match cipher.encrypt(&nonce, plaintext) {
        Ok(ct) => ct,
        Err(_) => return CryptoError::EncryptionFailed as i32,
    };

    // Write: [nonce][ciphertext+tag]
    let total_output = NONCE_SIZE + ciphertext_with_tag.len();
    if output.len() < total_output {
        return CryptoError::BufferTooSmall as i32;
    }

    output[..NONCE_SIZE].copy_from_slice(&nonce);
    output[NONCE_SIZE..total_output].copy_from_slice(&ciphertext_with_tag);

    total_output as i32
}

/// Decrypt data encrypted with AES-256-GCM.
///
/// # Arguments
/// * `key` - 32-byte encryption key (same key used for encryption)
/// * `encrypted` - Encrypted data in format: [nonce (12B)][ciphertext][tag (16B)]
/// * `output` - Output buffer (must be at least encrypted.len() - ENCRYPTION_OVERHEAD)
///
/// # Returns
/// Number of plaintext bytes written on success, negative error code on failure.
///
/// If the auth tag doesn't match (data was tampered), returns DecryptionFailed.
pub fn decrypt(key: &[u8; 32], encrypted: &[u8], output: &mut [u8]) -> i32 {
    if encrypted.len() < ENCRYPTION_OVERHEAD {
        return CryptoError::DecryptionFailed as i32;
    }

    let plaintext_size = encrypted.len() - ENCRYPTION_OVERHEAD;
    if output.len() < plaintext_size {
        return CryptoError::BufferTooSmall as i32;
    }

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Extract nonce from first 12 bytes
    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);

    // Decrypt (ciphertext+tag is everything after the nonce)
    let ciphertext_with_tag = &encrypted[NONCE_SIZE..];

    let plaintext = match cipher.decrypt(nonce, ciphertext_with_tag) {
        Ok(pt) => pt,
        Err(_) => return CryptoError::DecryptionFailed as i32,
    };

    output[..plaintext.len()].copy_from_slice(&plaintext);

    plaintext.len() as i32
}

/// Generate a cryptographically secure random 256-bit key.
pub fn generate_key(key_out: &mut [u8; 32]) {
    use rand::RngCore;
    OsRng.fill_bytes(key_out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut key = [0u8; 32];
        generate_key(&mut key);

        let plaintext = b"Hello, CyberGuard! This is secret content.";
        let mut encrypted = vec![0u8; plaintext.len() + ENCRYPTION_OVERHEAD];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Encrypt
        let enc_len = encrypt(&key, plaintext, &mut encrypted);
        assert!(enc_len > 0, "Encryption failed with code: {}", enc_len);
        assert_eq!(enc_len as usize, plaintext.len() + ENCRYPTION_OVERHEAD);

        // Decrypt
        let dec_len = decrypt(&key, &encrypted[..enc_len as usize], &mut decrypted);
        assert!(dec_len > 0, "Decryption failed with code: {}", dec_len);
        assert_eq!(dec_len as usize, plaintext.len());
        assert_eq!(&decrypted[..dec_len as usize], plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut key = [0u8; 32];
        generate_key(&mut key);

        let plaintext = b"Secret data";
        let mut encrypted = vec![0u8; plaintext.len() + ENCRYPTION_OVERHEAD];
        let mut decrypted = vec![0u8; plaintext.len()];

        let enc_len = encrypt(&key, plaintext, &mut encrypted);
        assert!(enc_len > 0);

        // Try decrypting with wrong key
        let wrong_key = [0xFFu8; 32];
        let dec_result = decrypt(&wrong_key, &encrypted[..enc_len as usize], &mut decrypted);
        assert_eq!(dec_result, CryptoError::DecryptionFailed as i32);
    }

    #[test]
    fn test_tampered_data_fails() {
        let mut key = [0u8; 32];
        generate_key(&mut key);

        let plaintext = b"Tamper test";
        let mut encrypted = vec![0u8; plaintext.len() + ENCRYPTION_OVERHEAD];
        let mut decrypted = vec![0u8; plaintext.len()];

        let enc_len = encrypt(&key, plaintext, &mut encrypted);
        assert!(enc_len > 0);

        // Tamper with ciphertext (flip a bit in the middle)
        let mid = (enc_len as usize) / 2;
        encrypted[mid] ^= 0x01;

        // Decryption should fail (auth tag won't match)
        let dec_result = decrypt(&key, &encrypted[..enc_len as usize], &mut decrypted);
        assert_eq!(dec_result, CryptoError::DecryptionFailed as i32);
    }

    #[test]
    fn test_different_nonce_each_time() {
        let mut key = [0u8; 32];
        generate_key(&mut key);

        let plaintext = b"Same plaintext";
        let mut enc1 = vec![0u8; plaintext.len() + ENCRYPTION_OVERHEAD];
        let mut enc2 = vec![0u8; plaintext.len() + ENCRYPTION_OVERHEAD];

        encrypt(&key, plaintext, &mut enc1);
        encrypt(&key, plaintext, &mut enc2);

        // Nonces (first 12 bytes) should differ
        assert_ne!(
            &enc1[..NONCE_SIZE], &enc2[..NONCE_SIZE],
            "Nonces must be unique per encryption"
        );

        // Ciphertext should also differ (because nonce differs)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_empty_plaintext() {
        let mut key = [0u8; 32];
        generate_key(&mut key);

        let plaintext = b"";
        let mut encrypted = vec![0u8; ENCRYPTION_OVERHEAD];
        let mut decrypted = vec![0u8; 0];

        let enc_len = encrypt(&key, plaintext, &mut encrypted);
        assert!(enc_len > 0);

        let dec_len = decrypt(&key, &encrypted[..enc_len as usize], &mut decrypted);
        assert_eq!(dec_len, 0);
    }

    #[test]
    fn test_buffer_too_small() {
        let key = [0u8; 32];
        let plaintext = b"Test data";
        let mut too_small = vec![0u8; 5]; // Way too small

        let result = encrypt(&key, plaintext, &mut too_small);
        assert_eq!(result, CryptoError::BufferTooSmall as i32);
    }
}
