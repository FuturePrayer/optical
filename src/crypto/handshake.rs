//! Pure post-quantum + PSK handshake state machine.
//!
//! Protocol (3-RTT):
//!   Client                              Server
//!     |--- ClientHello ------------------>|  ephemeral ML-KEM-768 pubkey + client_random + ML-DSA pubkey
//!     |<-- ServerHello -------------------|  ML-KEM ciphertext + server_random + ML-DSA pubkey
//!     |--- ClientFinished --------------->|  ML-DSA signature + HMAC(finished_key, transcript)
//!     |<-- ServerFinished ----------------|  ML-DSA signature + HMAC(finished_key, transcript)
//!
//! Security:
//!   - Forward secrecy: ML-KEM ephemeral keypair per handshake.
//!   - Anti-MITM: PSK participates in finished_mac_key derivation; attacker without PSK
//!     cannot forge the Finished HMAC.
//!   - Signature binding: ML-DSA signs the transcript hash as defense-in-depth.

use ml_dsa::{MlDsa65, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::config::Protocol;
use crate::crypto::kdf::{derive_session_keys, hmac_sha256};
use crate::crypto::pqdsa::{self, DsaKeyPair};
use crate::crypto::pqkem::{self, KemKeyPair};
use crate::error::{OpticalError, Result};

/// Handshake role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    Client,
    Server,
}

/// Result of a successful handshake: session keys + role.
#[derive(Clone)]
pub struct HandshakeResult {
    pub role: HandshakeRole,
    pub send_cipher: crate::crypto::aead::AeadCipher,
    pub recv_cipher: crate::crypto::aead::AeadCipher,
}

// ── Message types ──────────────────────────────────────────────────────────

pub const MSG_CLIENT_HELLO: u8 = 0x01;
pub const MSG_SERVER_HELLO: u8 = 0x02;
pub const MSG_CLIENT_FINISHED: u8 = 0x03;
pub const MSG_SERVER_FINISHED: u8 = 0x04;

/// ClientHello message.
pub struct ClientHello {
    pub kem_pubkey: Vec<u8>,
    pub client_random: [u8; 16],
    pub dsa_pubkey: Vec<u8>,
}

impl ClientHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 2 + self.kem_pubkey.len() + 16 + 2 + self.dsa_pubkey.len());
        buf.push(MSG_CLIENT_HELLO);
        encode_bytes(&mut buf, &self.kem_pubkey);
        buf.extend_from_slice(&self.client_random);
        encode_bytes(&mut buf, &self.dsa_pubkey);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let msg_type = take_u8(data, &mut pos)?;
        if msg_type != MSG_CLIENT_HELLO {
            return Err(OpticalError::Handshake(format!("expected ClientHello, got type {msg_type}")));
        }
        let kem_pubkey = take_bytes(data, &mut pos)?;
        let client_random = take_fixed::<16>(data, &mut pos)?;
        let dsa_pubkey = take_bytes(data, &mut pos)?;
        Ok(Self { kem_pubkey, client_random, dsa_pubkey })
    }
}

/// ServerHello message.
pub struct ServerHello {
    pub kem_ciphertext: Vec<u8>,
    pub server_random: [u8; 16],
    pub dsa_pubkey: Vec<u8>,
}

impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 2 + self.kem_ciphertext.len() + 16 + 2 + self.dsa_pubkey.len());
        buf.push(MSG_SERVER_HELLO);
        encode_bytes(&mut buf, &self.kem_ciphertext);
        buf.extend_from_slice(&self.server_random);
        encode_bytes(&mut buf, &self.dsa_pubkey);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let msg_type = take_u8(data, &mut pos)?;
        if msg_type != MSG_SERVER_HELLO {
            return Err(OpticalError::Handshake(format!("expected ServerHello, got type {msg_type}")));
        }
        let kem_ciphertext = take_bytes(data, &mut pos)?;
        let server_random = take_fixed::<16>(data, &mut pos)?;
        let dsa_pubkey = take_bytes(data, &mut pos)?;
        Ok(Self { kem_ciphertext, server_random, dsa_pubkey })
    }
}

/// Finished message (used for both client and server).
pub struct Finished {
    pub signature: Vec<u8>,
    pub hmac: [u8; 32],
}

impl Finished {
    pub fn encode(&self, msg_type: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + self.signature.len() + 32);
        buf.push(msg_type);
        encode_bytes_4(&mut buf, &self.signature);
        buf.extend_from_slice(&self.hmac);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let msg_type = take_u8(data, &mut pos)?;
        if msg_type != MSG_CLIENT_FINISHED && msg_type != MSG_SERVER_FINISHED {
            return Err(OpticalError::Handshake(format!("expected Finished, got type {msg_type}")));
        }
        let signature = take_bytes_4(data, &mut pos)?;
        let hmac = take_fixed::<32>(data, &mut pos)?;
        Ok(Self { signature, hmac })
    }

    /// Returns the message type byte from encoded data.
    #[allow(dead_code)]
    pub fn msg_type(data: &[u8]) -> u8 {
        data.first().copied().unwrap_or(0)
    }
}

// ── Handshake state ────────────────────────────────────────────────────────

/// Mutable state during the handshake process.
pub struct HandshakeState {
    role: HandshakeRole,
    psk: [u8; 32],
    dsa_keypair: DsaKeyPair,
    kem_keypair: Option<KemKeyPair>,
    peer_dsa_pubkey: Option<VerifyingKey<MlDsa65>>,
    transcript: Vec<u8>,
    /// (session_keys, finished_mac_key) — set after key derivation.
    keys: Option<(crate::crypto::kdf::SessionKeys, [u8; 32])>,
    // Server-side temporary storage between process_client_hello and create_hello
    kem_secret: Option<[u8; 32]>,
    kem_ciphertext: Option<Vec<u8>>,
    client_random: Option<[u8; 16]>,
}

impl HandshakeState {
    pub fn new(role: HandshakeRole, psk: [u8; 32], dsa_keypair: DsaKeyPair) -> Self {
        Self {
            role,
            psk,
            dsa_keypair,
            kem_keypair: None,
            peer_dsa_pubkey: None,
            transcript: Vec::new(),
            keys: None,
            kem_secret: None,
            kem_ciphertext: None,
            client_random: None,
        }
    }

    /// Compute SHA-256 of the transcript so far.
    fn transcript_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.transcript);
        hasher.finalize().into()
    }

    // ── Client side ──

    /// Client step 1: generate ephemeral KEM keypair and create ClientHello.
    pub fn client_create_hello(&mut self) -> Result<ClientHello> {
        if self.role != HandshakeRole::Client {
            return Err(OpticalError::Handshake("client_create_hello called on server".into()));
        }
        let kem_kp = pqkem::generate_keypair();
        let kem_pubkey = pqkem::encode_ek(&kem_kp.encapsulation_key);
        let client_random = crate::crypto::kdf::random_bytes();
        let dsa_pubkey = self.dsa_keypair.verifying_key().encode().to_vec();

        let hello = ClientHello {
            kem_pubkey,
            client_random,
            dsa_pubkey,
        };

        // Add to transcript
        let encoded = hello.encode();
        self.transcript.extend_from_slice(&encoded);
        self.kem_keypair = Some(kem_kp);

        Ok(hello)
    }

    /// Client step 2: process ServerHello, decapsulate KEM, derive session keys.
    pub fn client_process_server_hello(&mut self, hello: &ServerHello) -> Result<()> {
        if self.role != HandshakeRole::Client {
            return Err(OpticalError::Handshake("client_process_server_hello called on server".into()));
        }

        // Add to transcript
        self.transcript.extend_from_slice(&hello.encode());

        // Decode peer's DSA public key
        let peer_vk = pqdsa::decode_verifying_key(&hello.dsa_pubkey)?;
        self.peer_dsa_pubkey = Some(peer_vk);

        // Decapsulate KEM ciphertext
        let kem_kp = self
            .kem_keypair
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("KEM keypair not generated".into()))?;
        let kem_secret = pqkem::decapsulate(&kem_kp.decapsulation_key, &hello.kem_ciphertext)?;

        // Derive session keys
        let (session_keys, finished_mac_key) = derive_session_keys(
            &self.psk,
            &kem_secret,
            // client_random was added to transcript; we need to extract it.
            // Actually, we stored it in the ClientHello which is in the transcript.
            // Let's just pass the values we know.
            &self.extract_client_random()?,
            &hello.server_random,
        )?;
        self.keys = Some((session_keys, finished_mac_key));

        Ok(())
    }

    /// Client step 3: create ClientFinished (sign + HMAC transcript).
    pub fn client_create_finished(&mut self) -> Result<Finished> {
        if self.role != HandshakeRole::Client {
            return Err(OpticalError::Handshake("client_create_finished called on server".into()));
        }
        let (_session_keys, finished_mac_key) = self
            .keys
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("keys not derived yet".into()))?;

        let thash = self.transcript_hash();
        let signature = self.dsa_keypair.sign(&thash);
        let hmac = hmac_sha256(finished_mac_key, &thash);

        let finished = Finished { signature, hmac };

        // Add to transcript
        self.transcript.extend_from_slice(&finished.encode(MSG_CLIENT_FINISHED));

        Ok(finished)
    }

    /// Client step 4: verify ServerFinished.
    pub fn client_verify_server_finished(&mut self, finished: &Finished) -> Result<HandshakeResult> {
        if self.role != HandshakeRole::Client {
            return Err(OpticalError::Handshake("client_verify_server_finished called on server".into()));
        }

        let (_, finished_mac_key) = self
            .keys
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("keys not derived yet".into()))?;

        // The transcript now includes ClientHello + ServerHello + ClientFinished.
        let thash = self.transcript_hash();

        // Verify HMAC (PSK-based anti-MITM)
        let expected_hmac = hmac_sha256(finished_mac_key, &thash);
        if expected_hmac != finished.hmac {
            return Err(OpticalError::Handshake("ServerFinished HMAC verification failed (wrong PSK?)".into()));
        }

        // Verify ML-DSA signature (defense-in-depth)
        let peer_vk = self
            .peer_dsa_pubkey
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("peer DSA pubkey not set".into()))?;
        pqdsa::verify(peer_vk, &thash, &finished.signature)?;

        // Add ServerFinished to transcript (for completeness)
        self.transcript.extend_from_slice(&finished.encode(MSG_SERVER_FINISHED));

        let (session_keys, _) = self.keys.take().unwrap();
        Ok(self.build_result(session_keys))
    }

    // ── Server side ──

    /// Server step 1: process ClientHello, generate KEM keypair, encapsulate.
    pub fn server_process_client_hello(&mut self, hello: &ClientHello) -> Result<()> {
        if self.role != HandshakeRole::Server {
            return Err(OpticalError::Handshake("server_process_client_hello called on client".into()));
        }

        // Add to transcript
        self.transcript.extend_from_slice(&hello.encode());

        // Decode peer's DSA public key
        let peer_vk = pqdsa::decode_verifying_key(&hello.dsa_pubkey)?;
        self.peer_dsa_pubkey = Some(peer_vk);

        // Decode client's KEM encapsulation key
        let client_ek = pqkem::decode_ek(&hello.kem_pubkey)?;

        // Encapsulate to client's ek
        let (ciphertext, kem_secret) = pqkem::encapsulate(&client_ek)?;

        // Store KEM shared secret for later key derivation
        // We need to store it temporarily. Let's store in kem_keypair as None
        // and keep the secret separately.
        self.kem_secret = Some(kem_secret);
        self.kem_ciphertext = Some(ciphertext);
        self.client_random = Some(hello.client_random);

        Ok(())
    }

    /// Server step 2: create ServerHello and derive session keys.
    pub fn server_create_hello(&mut self) -> Result<ServerHello> {
        if self.role != HandshakeRole::Server {
            return Err(OpticalError::Handshake("server_create_hello called on client".into()));
        }

        let kem_ciphertext = self
            .kem_ciphertext
            .take()
            .ok_or_else(|| OpticalError::Handshake("KEM ciphertext not available".into()))?;
        let kem_secret = self
            .kem_secret
            .take()
            .ok_or_else(|| OpticalError::Handshake("KEM secret not available".into()))?;
        let client_random = self
            .client_random
            .ok_or_else(|| OpticalError::Handshake("client_random not set".into()))?;

        let server_random = crate::crypto::kdf::random_bytes();
        let dsa_pubkey = self.dsa_keypair.verifying_key().encode().to_vec();

        let hello = ServerHello {
            kem_ciphertext,
            server_random,
            dsa_pubkey,
        };

        // Add to transcript
        self.transcript.extend_from_slice(&hello.encode());

        // Derive session keys
        let (session_keys, finished_mac_key) =
            derive_session_keys(&self.psk, &kem_secret, &client_random, &server_random)?;
        self.keys = Some((session_keys, finished_mac_key));

        Ok(hello)
    }

    /// Server step 3: verify ClientFinished.
    pub fn server_verify_client_finished(&mut self, finished: &Finished) -> Result<()> {
        if self.role != HandshakeRole::Server {
            return Err(OpticalError::Handshake("server_verify_client_finished called on client".into()));
        }

        let (_, finished_mac_key) = self
            .keys
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("keys not derived yet".into()))?;

        // Transcript includes ClientHello + ServerHello
        let thash = self.transcript_hash();

        // Verify HMAC
        let expected_hmac = hmac_sha256(finished_mac_key, &thash);
        if expected_hmac != finished.hmac {
            return Err(OpticalError::Handshake("ClientFinished HMAC verification failed (wrong PSK?)".into()));
        }

        // Verify ML-DSA signature
        let peer_vk = self
            .peer_dsa_pubkey
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("peer DSA pubkey not set".into()))?;
        pqdsa::verify(peer_vk, &thash, &finished.signature)?;

        // Add ClientFinished to transcript
        self.transcript.extend_from_slice(&finished.encode(MSG_CLIENT_FINISHED));

        Ok(())
    }

    /// Server step 4: create ServerFinished.
    pub fn server_create_finished(&mut self) -> Result<(Finished, HandshakeResult)> {
        if self.role != HandshakeRole::Server {
            return Err(OpticalError::Handshake("server_create_finished called on client".into()));
        }

        let (_session_keys, finished_mac_key) = self
            .keys
            .as_ref()
            .ok_or_else(|| OpticalError::Handshake("keys not derived yet".into()))?;

        // Transcript includes ClientHello + ServerHello + ClientFinished
        let thash = self.transcript_hash();
        let signature = self.dsa_keypair.sign(&thash);
        let hmac = hmac_sha256(finished_mac_key, &thash);

        let finished = Finished { signature, hmac };

        // Add ServerFinished to transcript
        self.transcript.extend_from_slice(&finished.encode(MSG_SERVER_FINISHED));

        let (session_keys, _) = self.keys.take().unwrap();
        Ok((finished, self.build_result(session_keys)))
    }

    // ── Helpers ──

    fn build_result(&self, session_keys: crate::crypto::kdf::SessionKeys) -> HandshakeResult {
        let (send_cipher, recv_cipher) = match self.role {
            HandshakeRole::Client => (
                crate::crypto::aead::AeadCipher::new(&session_keys.c2s_key),
                crate::crypto::aead::AeadCipher::new(&session_keys.s2c_key),
            ),
            HandshakeRole::Server => (
                crate::crypto::aead::AeadCipher::new(&session_keys.s2c_key),
                crate::crypto::aead::AeadCipher::new(&session_keys.c2s_key),
            ),
        };
        HandshakeResult {
            role: self.role,
            send_cipher,
            recv_cipher,
        }
    }

    /// Extract client_random from the transcript (first ClientHello message).
    fn extract_client_random(&self) -> Result<[u8; 16]> {
        // The first byte of transcript is MSG_CLIENT_HELLO (0x01)
        // followed by [2B ek_len][ek][16B random][2B vk_len][vk]
        let data = &self.transcript;
        if data.is_empty() || data[0] != MSG_CLIENT_HELLO {
            return Err(OpticalError::Handshake("transcript does not start with ClientHello".into()));
        }
        let mut pos = 1;
        let _ek = take_bytes(data, &mut pos)?;
        let random = take_fixed::<16>(data, &mut pos)?;
        Ok(random)
    }
}

// ── Binary encoding helpers ────────────────────────────────────────────────

fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn encode_bytes_4(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn take_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    let v = data.get(*pos).copied().ok_or_else(|| OpticalError::Handshake("unexpected end of message".into()))?;
    *pos += 1;
    Ok(v)
}

fn take_bytes(data: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let len_bytes: [u8; 2] = data[*pos..*pos + 2]
        .try_into()
        .map_err(|_| OpticalError::Handshake("unexpected end of message (len)".into()))?;
    *pos += 2;
    let len = u16::from_be_bytes(len_bytes) as usize;
    let bytes = data[*pos..*pos + len]
        .to_vec();
    *pos += len;
    if *pos > data.len() {
        return Err(OpticalError::Handshake("unexpected end of message (data)".into()));
    }
    Ok(bytes)
}

fn take_bytes_4(data: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let len_bytes: [u8; 4] = data[*pos..*pos + 4]
        .try_into()
        .map_err(|_| OpticalError::Handshake("unexpected end of message (len4)".into()))?;
    *pos += 4;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let bytes = data[*pos..*pos + len]
        .to_vec();
    *pos += len;
    if *pos > data.len() {
        return Err(OpticalError::Handshake("unexpected end of message (data4)".into()))?;
    }
    Ok(bytes)
}

fn take_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let arr: [u8; N] = data[*pos..*pos + N]
        .try_into()
        .map_err(|_| OpticalError::Handshake("unexpected end of message (fixed)".into()))?;
    *pos += N;
    Ok(arr)
}

/// Frame type for OPEN messages, indicating the protocol to dial.
pub fn proto_to_byte(proto: Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 0x01,
        Protocol::Udp => 0x02,
    }
}

#[allow(dead_code)]
pub fn byte_to_proto(b: u8) -> Result<Protocol> {
    match b {
        0x01 => Ok(Protocol::Tcp),
        0x02 => Ok(Protocol::Udp),
        _ => Err(OpticalError::FrameDecode(format!("unknown protocol byte: {b}"))),
    }
}
