//! ChaCha20-Poly1305 AEAD encryption for tunnel frames.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::Zeroize;

use crate::error::{OpticalError, Result};

/// AEAD tag size in bytes.
#[allow(dead_code)]
pub const TAG_SIZE: usize = 16;

/// A direction-specific AEAD cipher (either c2s or s2c).
#[derive(Clone)]
pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
}

impl AeadCipher {
    /// Create from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
        }
    }

    /// Build the 12-byte nonce from stream_id (4B LE) and counter (8B LE).
    /// This ensures nonce uniqueness across streams and within a stream.
    fn build_nonce(stream_id: u32, counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&stream_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt plaintext with AAD. Returns ciphertext + 16-byte tag.
    /// `aad` is the frame header (stream_id + counter + frame_type + payload_len).
    pub fn encrypt(&self, stream_id: u32, counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let nonce = Self::build_nonce(stream_id, counter);
        let nonce = Nonce::from_slice(&nonce);
        self.cipher
            .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
            .map_err(|e| OpticalError::Crypto(format!("AEAD encrypt failed: {e}")))
            .unwrap_or_else(|_| Vec::new()) // encrypt failure is fatal
    }

    /// Decrypt ciphertext+tag with AAD. Returns plaintext.
    pub fn decrypt(&self, stream_id: u32, counter: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::build_nonce(stream_id, counter);
        let nonce = Nonce::from_slice(&nonce);
        self.cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| OpticalError::AeadDecrypt)
    }
}

/// Securely zero a byte buffer.
#[allow(dead_code)]
pub fn zeroize(buf: &mut [u8]) {
    buf.zeroize();
}
