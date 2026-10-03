use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};

const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Fill an array with cryptographically secure random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate a fresh 32-byte key, hex-encoded (for `totp-server keygen`).
pub fn generate_key_hex() -> String {
    hex::encode(random_bytes::<KEY_LEN>())
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key must be {KEY_LEN} bytes ({} hex chars)", KEY_LEN * 2)]
    BadKey,
    #[error("ciphertext is malformed or was tampered with")]
    Unsealable,
}

/// Authenticated encryption (XChaCha20-Poly1305) for TOTP secrets at rest.
///
/// Sealed blobs are `nonce (24B) || ciphertext+tag` and are bound to an
/// additional-data string (the user's email), so a blob copied onto another
/// user's row fails to decrypt.
pub struct SecretCipher {
    cipher: XChaCha20Poly1305,
}

impl SecretCipher {
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key.trim()).map_err(|_| CryptoError::BadKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::BadKey);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&bytes).map_err(|_| CryptoError::BadKey)?;
        Ok(Self { cipher })
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Unsealable)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() <= NONCE_LEN {
            return Err(CryptoError::Unsealable);
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Unsealable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let cipher = SecretCipher::from_hex_key(&generate_key_hex()).unwrap();
        let sealed = cipher.seal(b"super-secret", b"user@example.com").unwrap();
        let opened = cipher.open(&sealed, b"user@example.com").unwrap();
        assert_eq!(opened, b"super-secret");
    }

    #[test]
    fn open_fails_with_wrong_aad() {
        let cipher = SecretCipher::from_hex_key(&generate_key_hex()).unwrap();
        let sealed = cipher.seal(b"super-secret", b"a@example.com").unwrap();
        assert!(cipher.open(&sealed, b"b@example.com").is_err());
    }

    #[test]
    fn open_fails_when_tampered() {
        let cipher = SecretCipher::from_hex_key(&generate_key_hex()).unwrap();
        let mut sealed = cipher.seal(b"super-secret", b"a@example.com").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(cipher.open(&sealed, b"a@example.com").is_err());
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(SecretCipher::from_hex_key("abcd").is_err());
        assert!(SecretCipher::from_hex_key("zz".repeat(32).as_str()).is_err());
    }
}
