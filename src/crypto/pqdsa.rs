//! ML-DSA-65 digital signature wrappers and key file I/O.

use ml_dsa::{
    self, Generate, Keypair, MlDsa65, Seed, Signature, SigningKey, Signer,
    Verifier, VerifyingKey,
};
use std::path::Path;

use crate::error::{OpticalError, Result};

/// ML-DSA-65 seed (private key) size: 32 bytes.
pub const SEED_SIZE: usize = 32;
/// ML-DSA-65 verifying key (public key) size: 1952 bytes.
pub const VK_SIZE: usize = 1952;
/// ML-DSA-65 signature size: 3309 bytes.
#[allow(dead_code)]
pub const SIG_SIZE: usize = 3309;

/// A loaded ML-DSA-65 key pair (cloneable for sharing across tasks).
#[derive(Clone)]
pub struct DsaKeyPair {
    pub signing_key: SigningKey<MlDsa65>,
}

impl DsaKeyPair {
    /// Generate a new ML-DSA-65 key pair using the system CSPRNG.
    pub fn generate() -> Self {
        let sk = SigningKey::<MlDsa65>::generate();
        Self { signing_key: sk }
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        self.signing_key.verifying_key()
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature<MlDsa65> = self.signing_key.sign(msg);
        sig.encode().to_vec()
    }

    /// Encode the private key as a 32-byte seed.
    pub fn encode_seed(&self) -> Vec<u8> {
        self.signing_key.to_seed().to_vec()
    }
}

/// Verify a signature using a verifying key.
pub fn verify(vk: &VerifyingKey<MlDsa65>, msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let sig: Signature<MlDsa65> = sig_bytes
        .try_into()
        .map_err(|_| OpticalError::Crypto("invalid signature length".into()))?;
    vk.verify(msg, &sig)
        .map_err(|_| OpticalError::Crypto("ML-DSA signature verification failed".into()))
}

/// Decode a verifying key from raw bytes.
pub fn decode_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>> {
    let arr: ml_dsa::EncodedVerifyingKey<MlDsa65> = bytes
        .try_into()
        .map_err(|_| OpticalError::Crypto(format!("invalid verifying key length: expected {VK_SIZE}, got {}", bytes.len())))?;
    Ok(VerifyingKey::<MlDsa65>::decode(&arr))
}

/// Load a key pair from seed and public key files.
pub fn load_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
) -> Result<DsaKeyPair> {
    let seed_bytes = std::fs::read(private_key_path).map_err(OpticalError::Io)?;
    if seed_bytes.len() != SEED_SIZE {
        return Err(OpticalError::Crypto(format!(
            "private key file must be {SEED_SIZE} bytes (seed format), got {}",
            seed_bytes.len()
        )));
    }
    let mut seed_arr = Seed::default();
    seed_arr.as_mut_slice().copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_arr);

    // Verify public key matches
    let vk_bytes = std::fs::read(public_key_path).map_err(OpticalError::Io)?;
    let expected_vk = decode_verifying_key(&vk_bytes)?;
    let actual_vk = signing_key.verifying_key();
    if expected_vk.encode() != actual_vk.encode() {
        return Err(OpticalError::Crypto(
            "public key does not match private key seed".into(),
        ));
    }

    Ok(DsaKeyPair { signing_key })
}

/// Generate a new ML-DSA-65 key pair and write to files.
/// Private key is stored as a 32-byte seed; public key as 1952 raw bytes.
pub fn keygen_to_files(private_key_path: &Path, public_key_path: &Path) -> Result<()> {
    let kp = DsaKeyPair::generate();

    // Create parent directories if needed
    if let Some(parent) = private_key_path.parent() {
        std::fs::create_dir_all(parent).map_err(OpticalError::Io)?;
    }
    if let Some(parent) = public_key_path.parent() {
        std::fs::create_dir_all(parent).map_err(OpticalError::Io)?;
    }

    // Write private key (seed)
    let seed = kp.encode_seed();
    std::fs::write(private_key_path, &seed).map_err(OpticalError::Io)?;

    // Write public key
    let vk_bytes = kp.verifying_key().encode();
    std::fs::write(public_key_path, vk_bytes.as_slice()).map_err(OpticalError::Io)?;

    Ok(())
}
