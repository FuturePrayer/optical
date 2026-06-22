//! ML-KEM-768 key encapsulation wrappers.

use ml_kem::{
    self, DecapsulationKey768, EncapsulationKey768, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};

use crate::error::{OpticalError, Result};

/// ML-KEM-768 encapsulation key size in bytes.
pub const EK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
#[allow(dead_code)]
pub const CT_SIZE: usize = 1088;
/// ML-KEM-768 shared key size in bytes.
#[allow(dead_code)]
pub const SHARED_KEY_SIZE: usize = 32;

/// An ephemeral ML-KEM-768 key pair generated for each handshake.
pub struct KemKeyPair {
    pub decapsulation_key: DecapsulationKey768,
    pub encapsulation_key: EncapsulationKey768,
}

/// Generate an ephemeral ML-KEM-768 key pair using the system CSPRNG.
pub fn generate_keypair() -> KemKeyPair {
    let (dk, ek) = MlKem768::generate_keypair();
    KemKeyPair {
        decapsulation_key: dk,
        encapsulation_key: ek,
    }
}

/// Serialize an encapsulation key to bytes.
pub fn encode_ek(ek: &EncapsulationKey768) -> Vec<u8> {
    ek.to_bytes().to_vec()
}

/// Deserialize an encapsulation key from bytes.
pub fn decode_ek(bytes: &[u8]) -> Result<EncapsulationKey768> {
    let key_arr: ml_kem::Key<EncapsulationKey768> = bytes
        .try_into()
        .map_err(|_| OpticalError::Crypto(format!("invalid encapsulation key length: expected {EK_SIZE}, got {}", bytes.len())))?;
    EncapsulationKey768::new(&key_arr)
        .map_err(|_| OpticalError::Crypto("invalid encapsulation key (failed validation)".into()))
}

/// Encapsulate a shared secret to the given encapsulation key.
/// Returns (ciphertext_bytes, shared_secret).
pub fn encapsulate(ek: &EncapsulationKey768) -> Result<(Vec<u8>, [u8; 32])> {
    let (ct, ss) = ek.encapsulate();
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());
    Ok((ct.to_vec(), ss_bytes))
}

/// Decapsulate a shared secret from the given ciphertext.
pub fn decapsulate(dk: &DecapsulationKey768, ct_bytes: &[u8]) -> Result<[u8; 32]> {
    let ss = dk
        .decapsulate_slice(ct_bytes)
        .map_err(|_| OpticalError::Crypto("invalid ciphertext length".into()))?;
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_slice());
    Ok(ss_bytes)
}
