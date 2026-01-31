use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer};

pub type PublicKey = VerifyingKey;

pub struct Keypair {
    pub secret: SigningKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn from_seed_bytes(seed: &[u8; 32]) -> anyhow::Result<Self> {
        let sk = SigningKey::from_bytes(seed);
        let pk = VerifyingKey::from(&sk);
        Ok(Keypair { secret: sk, public: pk })
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Self::from_seed_bytes(bytes)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.secret.sign(msg)
    }

    pub fn secret_to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

pub fn public_from_bytes(b: &[u8; 32]) -> anyhow::Result<PublicKey> {
    let pk = VerifyingKey::from_bytes(b)?;
    Ok(pk)
}

pub fn signature_from_slice(v: &[u8]) -> anyhow::Result<Signature> {
    if v.len() != 64 {
        return Err(anyhow::anyhow!("invalid signature length: {}", v.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&v[..64]);
    Ok(Signature::from_bytes(&arr))
}
