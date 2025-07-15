//! src/crypto.rs – shared PQ-signing helpers

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_sphincsplus::sphincssha2256ssimple as sphincs;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use pqcrypto_traits::sign::{
    DetachedSignature as _,
    PublicKey as _,
    SignedMessage,          // <-- add this
};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PublicKeys {
    pub dilithium5: String,
    pub sphincs: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Signatures {
    pub dilithium5: String,
    pub sphincs: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Packet {
    pub data: String,
    pub sig: Signatures,
    pub pubkey: PublicKeys,
    pub filename: String,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Hybrid signer (Dilithium-5 + SPHINCS+ SHA-256-256s-simple)
// ---------------------------------------------------------------------------
pub struct HybridSigner {
    d_pk: dilithium5::PublicKey,
    d_sk: dilithium5::SecretKey,
    s_pk: sphincs::PublicKey,
    s_sk: sphincs::SecretKey,
}

impl HybridSigner {
    pub fn new() -> Self {
        let (d_pk, d_sk) = dilithium5::keypair();
        let (s_pk, s_sk) = sphincs::keypair();
        Self { d_pk, d_sk, s_pk, s_sk }
    }

    pub fn sign(&self, data: &[u8]) -> Signatures {
        let d_sig = dilithium5::detached_sign(data, &self.d_sk);
        let s_sig = sphincs::detached_sign(data, &self.s_sk);
        Signatures {
            dilithium5: general_purpose::STANDARD.encode(d_sig.as_bytes()),
            sphincs:    general_purpose::STANDARD.encode(s_sig.as_bytes()),
        }
    }

    pub fn export_public(&self) -> PublicKeys {
        PublicKeys {
            dilithium5: general_purpose::STANDARD.encode(self.d_pk.as_bytes()),
            sphincs:    general_purpose::STANDARD.encode(self.s_pk.as_bytes()),
        }
    }
}

// ---------------------------------------------------------------------------
// Verify both signatures
// ---------------------------------------------------------------------------
pub fn verify_hybrid(pkt: &Packet) -> Result<bool> {
    // -- decode public keys -------------------------------------------------
    let d_pk = dilithium5::PublicKey::from_bytes(
        &general_purpose::STANDARD.decode(&pkt.pubkey.dilithium5)?
    )?;
    let s_pk = sphincs::PublicKey::from_bytes(
        &general_purpose::STANDARD.decode(&pkt.pubkey.sphincs)?
    )?;

    // -- original message bytes --------------------------------------------
    let msg = general_purpose::STANDARD.decode(&pkt.data)?;

    // -- detached sigs → SignedMessage buffers ------------------------------
    let d_sm = {
        let mut v = dilithium5::DetachedSignature::from_bytes(
            &general_purpose::STANDARD.decode(&pkt.sig.dilithium5)?
        )?.as_bytes().to_vec();
        v.extend_from_slice(&msg);
        dilithium5::SignedMessage::from_bytes(&v)?
    };

    let s_sm = {
        let mut v = sphincs::DetachedSignature::from_bytes(
            &general_purpose::STANDARD.decode(&pkt.sig.sphincs)?
        )?.as_bytes().to_vec();
        v.extend_from_slice(&msg);
        sphincs::SignedMessage::from_bytes(&v)?
    };

    // -- verify -------------------------------------------------------------
    let d_ok = dilithium5::open(&d_sm, &d_pk).is_ok();
    let s_ok = sphincs::open(&s_sm, &s_pk).is_ok();
    Ok(d_ok && s_ok)
}
