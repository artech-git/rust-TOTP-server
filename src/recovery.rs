use anyhow::anyhow;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::config::Argon2Config;

/// Unambiguous alphabet (no 0/O, 1/I/L, U/V confusion): 30 symbols,
/// 10 symbols per code ≈ 49 bits of entropy.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
const CODE_LEN: usize = 10;

/// Generate `count` one-time recovery codes, formatted `XXXXX-XXXXX`.
pub fn generate_codes(count: u8) -> Vec<String> {
    (0..count).map(|_| generate_code()).collect()
}

fn generate_code() -> String {
    let mut symbols = Vec::with_capacity(CODE_LEN);
    while symbols.len() < CODE_LEN {
        for byte in crate::crypto::random_bytes::<16>() {
            // Rejection sampling: 240 = 8 * 30 keeps the distribution uniform.
            if byte < 240 {
                symbols.push(ALPHABET[(byte % 30) as usize]);
                if symbols.len() == CODE_LEN {
                    break;
                }
            }
        }
    }
    let text = String::from_utf8(symbols).expect("alphabet is ASCII");
    format!("{}-{}", &text[..5], &text[5..])
}

/// Canonical form used for hashing and verification: uppercase, alphanumerics
/// only (so users may type codes with or without the dash).
pub fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Argon2id hasher for recovery codes.
pub struct RecoveryHasher {
    argon2: Argon2<'static>,
}

impl RecoveryHasher {
    pub fn new(cfg: &Argon2Config) -> anyhow::Result<Self> {
        let params = Params::new(cfg.memory_kib, cfg.iterations, cfg.parallelism, None)
            .map_err(|e| anyhow!("invalid argon2 parameters: {e}"))?;
        Ok(Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        })
    }

    pub fn hash(&self, code: &str) -> anyhow::Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(normalize(code).as_bytes(), &salt)
            .map_err(|e| anyhow!("argon2 hashing failed: {e}"))?;
        Ok(hash.to_string())
    }

    pub fn verify(&self, code: &str, phc: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(phc) else {
            return false;
        };
        self.argon2
            .verify_password(normalize(code).as_bytes(), &parsed)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_hasher() -> RecoveryHasher {
        RecoveryHasher::new(&Argon2Config {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        })
        .unwrap()
    }

    #[test]
    fn codes_have_expected_shape_and_are_unique() {
        let codes = generate_codes(20);
        assert_eq!(codes.len(), 20);
        for code in &codes {
            assert_eq!(code.len(), 11);
            assert_eq!(code.as_bytes()[5], b'-');
            assert!(normalize(code).bytes().all(|b| ALPHABET.contains(&b)));
        }
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn hash_verify_roundtrip_and_normalization() {
        let hasher = fast_hasher();
        let code = generate_code();
        let phc = hasher.hash(&code).unwrap();

        assert!(hasher.verify(&code, &phc));
        assert!(hasher.verify(&code.to_lowercase(), &phc));
        assert!(hasher.verify(&code.replace('-', " "), &phc));
        assert!(!hasher.verify("AAAAA-AAAAA", &phc));
        assert!(!hasher.verify(&code, "not-a-phc-string"));
    }
}
