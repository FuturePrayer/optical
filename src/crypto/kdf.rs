//! HKDF key schedule and PSK generation.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{OpticalError, Result};

/// Generate a random 32-byte PSK using the system CSPRNG.
pub fn generate_psk() -> [u8; 32] {
    let mut psk = [0u8; 32];
    getrandom::fill(&mut psk).expect("getrandom failed");
    psk
}

/// Generate random bytes using the system CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("getrandom failed");
    buf
}

/// Session keys derived from the handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Client → server direction AEAD key.
    pub c2s_key: [u8; 32],
    /// Server → client direction AEAD key.
    pub s2c_key: [u8; 32],
}

/// Derive session keys from the KEM shared secret, randoms, and PSK.
///
/// Key schedule:
/// 1. early_secret = HKDF-Extract(salt=0, IKM=PSK)
/// 2. master_secret = HKDF-Extract(salt=early_secret, IKM=kem_secret || client_random || server_random)
/// 3. c2s_key = HKDF-Expand(master, "optical c2s", 32)
/// 4. s2c_key = HKDF-Expand(master, "optical s2c", 32)
/// 5. finished_mac_key = HKDF-Expand(master, "optical finished", 32)
pub fn derive_session_keys(
    psk: &[u8; 32],
    kem_secret: &[u8; 32],
    client_random: &[u8; 16],
    server_random: &[u8; 16],
) -> Result<(SessionKeys, [u8; 32])> {
    // Step 1: early_secret = HKDF-Extract(salt=zeros, IKM=PSK)
    let salt_zero = [0u8; 32];
    let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&salt_zero), psk);

    // Step 2: master_secret = HKDF-Extract(salt=early_secret, IKM=kem_secret || randoms)
    let mut ikm = Vec::with_capacity(32 + 16 + 16);
    ikm.extend_from_slice(kem_secret);
    ikm.extend_from_slice(client_random);
    ikm.extend_from_slice(server_random);
    let (master_secret, _) = Hkdf::<Sha256>::extract(Some(&early_secret), &ikm);

    // Step 3-5: expand
    let hk = Hkdf::<Sha256>::from_prk(&master_secret)
        .map_err(|e| OpticalError::Crypto(format!("HKDF from_prk failed: {e}")))?;

    let mut c2s_key = [0u8; 32];
    hk.expand(b"optical c2s key", &mut c2s_key)
        .map_err(|e| OpticalError::Crypto(format!("HKDF expand c2s failed: {e}")))?;

    let mut s2c_key = [0u8; 32];
    hk.expand(b"optical s2c key", &mut s2c_key)
        .map_err(|e| OpticalError::Crypto(format!("HKDF expand s2c failed: {e}")))?;

    let mut finished_mac_key = [0u8; 32];
    hk.expand(b"optical finished mac", &mut finished_mac_key)
        .map_err(|e| OpticalError::Crypto(format!("HKDF expand finished failed: {e}")))?;

    Ok((
        SessionKeys { c2s_key, s2c_key },
        finished_mac_key,
    ))
}

/// Compute HMAC-SHA256 over data with the given key.
pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key size is always 32");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
