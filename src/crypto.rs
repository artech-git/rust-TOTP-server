use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Fill an array with cryptographically secure random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system randomness is unavailable");
    buf
}

/// Generate a fresh 32-byte key, hex-encoded (for `totp-server keygen`).
pub fn generate_key_hex() -> String {
    hex::encode(random_bytes::<KEY_LEN>())
}

/// Short, stable label for a key, stored next to the data it sealed so a
/// rotation can tell which key to use. Derived by hashing with a domain
/// prefix, so it reveals nothing about the key.
pub fn key_id(key: &[u8]) -> String {
    let digest = Sha256::new_with_prefix(b"totp-server/key-id/v1")
        .chain_update(key)
        .finalize();
    hex::encode(&digest[..8])
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key must be {KEY_LEN} bytes ({} hex chars)", KEY_LEN * 2)]
    BadKey,
    #[error("ciphertext is malformed or was tampered with")]
    Unsealable,
    #[error("sealed with a key that is not configured; add it to security.retired_encryption_keys")]
    UnknownKey,
}

fn decode_key(hex_key: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| CryptoError::BadKey)?;
    bytes.try_into().map_err(|_| CryptoError::BadKey)
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
        Ok(Self::with_id(hex_key)?.1)
    }

    /// Build the cipher and the [`key_id`] of its key.
    pub fn with_id(hex_key: &str) -> Result<(String, Self), CryptoError> {
        let key = decode_key(hex_key)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::BadKey)?;
        Ok((key_id(&key), Self { cipher }))
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = XNonce::from(nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
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
        let nonce = XNonce::try_from(nonce_bytes).map_err(|_| CryptoError::Unsealable)?;
        self.cipher
            .decrypt(&nonce, Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Unsealable)
    }
}

/// A sealed blob that has been opened.
pub struct Opened {
    pub plaintext: Vec<u8>,
    /// The blob was sealed by a retired key, or before key ids were recorded:
    /// re-seal it with the active key when convenient so the old key can
    /// eventually be dropped.
    pub needs_reseal: bool,
}

/// The active encryption key plus retired keys that can still open old blobs.
///
/// New data is always sealed with the active key. Rotation is: generate a new
/// key, move the current one to `security.retired_encryption_keys`, deploy;
/// rows are re-sealed as they are used (or all at once with
/// `totp-server rekey`), after which the retired key can be removed.
pub struct KeyRing {
    active_id: String,
    active: SecretCipher,
    retired: Vec<(String, SecretCipher)>,
}

impl KeyRing {
    pub fn new(active_hex: &str, retired_hex: &[String]) -> Result<Self, CryptoError> {
        let (active_id, active) = SecretCipher::with_id(active_hex)?;
        let mut retired: Vec<(String, SecretCipher)> = Vec::new();
        for hex_key in retired_hex {
            let (id, cipher) = SecretCipher::with_id(hex_key)?;
            if id != active_id && !retired.iter().any(|(known, _)| *known == id) {
                retired.push((id, cipher));
            }
        }
        Ok(Self {
            active_id,
            active,
            retired,
        })
    }

    /// Id of the key new data is sealed with.
    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    pub fn retired_ids(&self) -> impl Iterator<Item = &str> {
        self.retired.iter().map(|(id, _)| id.as_str())
    }

    /// Seal with the active key; record [`KeyRing::active_id`] alongside.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.active.seal(plaintext, aad)
    }

    /// Open a blob sealed by the key labelled `key_id`. Blobs from before key
    /// ids were recorded (`None`) are tried against the active key first and
    /// then each retired key.
    pub fn open(
        &self,
        blob: &[u8],
        key_id: Option<&str>,
        aad: &[u8],
    ) -> Result<Opened, CryptoError> {
        match key_id {
            Some(id) if id == self.active_id => Ok(Opened {
                plaintext: self.active.open(blob, aad)?,
                needs_reseal: false,
            }),
            Some(id) => {
                let (_, cipher) = self
                    .retired
                    .iter()
                    .find(|(known, _)| known == id)
                    .ok_or(CryptoError::UnknownKey)?;
                Ok(Opened {
                    plaintext: cipher.open(blob, aad)?,
                    needs_reseal: true,
                })
            }
            None => {
                let candidates =
                    std::iter::once(&self.active).chain(self.retired.iter().map(|(_, c)| c));
                for cipher in candidates {
                    if let Ok(plaintext) = cipher.open(blob, aad) {
                        // Even when the active key opened it, re-sealing
                        // records the key id so later rotations stay cheap.
                        return Ok(Opened {
                            plaintext,
                            needs_reseal: true,
                        });
                    }
                }
                Err(CryptoError::Unsealable)
            }
        }
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

    #[test]
    fn key_ids_are_stable_and_distinct() {
        let a = generate_key_hex();
        let b = generate_key_hex();
        assert_eq!(
            key_id(&hex::decode(&a).unwrap()),
            key_id(&hex::decode(&a).unwrap())
        );
        assert_ne!(
            key_id(&hex::decode(&a).unwrap()),
            key_id(&hex::decode(&b).unwrap())
        );
        assert_eq!(key_id(&hex::decode(&a).unwrap()).len(), 16);
    }

    #[test]
    fn ring_opens_retired_keys_and_flags_them_for_reseal() {
        let old = generate_key_hex();
        let new = generate_key_hex();
        let old_ring = KeyRing::new(&old, &[]).unwrap();
        let sealed = old_ring.seal(b"secret", b"aad").unwrap();
        let old_id = old_ring.active_id().to_string();

        // Rotation: new active key, old key retired.
        let ring = KeyRing::new(&new, std::slice::from_ref(&old)).unwrap();
        assert_ne!(ring.active_id(), old_id);
        let opened = ring.open(&sealed, Some(&old_id), b"aad").unwrap();
        assert_eq!(opened.plaintext, b"secret");
        assert!(opened.needs_reseal);

        let resealed = ring.seal(&opened.plaintext, b"aad").unwrap();
        let again = ring
            .open(&resealed, Some(ring.active_id()), b"aad")
            .unwrap();
        assert_eq!(again.plaintext, b"secret");
        assert!(!again.needs_reseal);

        // Once the old key is dropped, its blobs are unreadable by id...
        let without_old = KeyRing::new(&new, &[]).unwrap();
        assert!(matches!(
            without_old.open(&sealed, Some(&old_id), b"aad"),
            Err(CryptoError::UnknownKey)
        ));
        // ...but the re-sealed copy still opens.
        assert!(
            without_old
                .open(&resealed, Some(ring.active_id()), b"aad")
                .is_ok()
        );
    }

    #[test]
    fn ring_tries_every_key_for_blobs_without_an_id() {
        let old = generate_key_hex();
        let new = generate_key_hex();
        let sealed = KeyRing::new(&old, &[])
            .unwrap()
            .seal(b"legacy", b"aad")
            .unwrap();

        let ring = KeyRing::new(&new, &[old]).unwrap();
        let opened = ring.open(&sealed, None, b"aad").unwrap();
        assert_eq!(opened.plaintext, b"legacy");
        assert!(opened.needs_reseal);

        assert!(
            KeyRing::new(&new, &[])
                .unwrap()
                .open(&sealed, None, b"aad")
                .is_err()
        );
    }

    #[test]
    fn ring_ignores_duplicate_and_active_keys_in_the_retired_list() {
        let active = generate_key_hex();
        let old = generate_key_hex();
        let ring = KeyRing::new(&active, &[active.clone(), old.clone(), old]).unwrap();
        assert_eq!(ring.retired_ids().count(), 1);
    }
}
