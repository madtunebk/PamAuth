use zeroize::Zeroize;

#[cfg(feature = "argon2")]
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, SaltString},
    Argon2, PasswordHasher, PasswordVerifier,
};
#[cfg(feature = "sha-crypt")]
use sha_crypt::{sha512_check, sha512_simple, Sha512Params};

#[derive(Debug)]
pub enum PinHashError {
    UnsupportedScheme,
    HashFailure(String),
    ParseFailure(String),
}

impl std::fmt::Display for PinHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinHashError::UnsupportedScheme => write!(f, "unsupported hash scheme"),
            PinHashError::HashFailure(e) => write!(f, "hash failure: {e}"),
            PinHashError::ParseFailure(e) => write!(f, "parse failure: {e}"),
        }
    }
}
impl std::error::Error for PinHashError {}

#[derive(Clone, Copy, Debug)]
pub enum Scheme {
    Sha512Crypt,
    Argon2id,
}

pub fn scheme_from_env() -> Scheme {
    match std::env::var("PIN_SCHEME")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "argon2" | "argon2id" => Scheme::Argon2id,
        _ => Scheme::Sha512Crypt,
    }
}

pub fn hash_pin(pin: &mut String) -> Result<String, PinHashError> {
    let scheme = scheme_from_env();
    let out = match scheme {
        Scheme::Sha512Crypt => {
            #[cfg(feature = "sha-crypt")]
            {
                let params = Sha512Params::default();
                sha512_simple(pin, &params)
                    .map_err(|e| PinHashError::HashFailure(format!("{e:?}")))?
            }
            #[cfg(not(feature = "sha-crypt"))]
            {
                return Err(PinHashError::UnsupportedScheme);
            }
        }
        Scheme::Argon2id => {
            #[cfg(feature = "argon2")]
            {
                let salt = SaltString::generate(&mut OsRng);
                // Allow tuning via env vars (fallback to Argon2::default())
                let argon = {
                    let base = Argon2::default();
                    if let (Ok(m), Ok(t), Ok(p)) = (
                        std::env::var("PIN_ARGON2_M_COST").unwrap_or_default().parse::<u32>(),
                        std::env::var("PIN_ARGON2_T_COST").unwrap_or_default().parse::<u32>(),
                        std::env::var("PIN_ARGON2_P_COST").unwrap_or_default().parse::<u32>(),
                    ) {
                        if m > 0 && t > 0 && p > 0 {
                            use argon2::{Algorithm, Params, Version};
                            if let Ok(params) = Params::new(m, t, p, None) {
                                Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                            } else {
                                base
                            }
                        } else {
                            base
                        }
                    } else {
                        base
                    }
                };
                argon
                    .hash_password(pin.as_bytes(), &salt)
                    .map_err(|e| PinHashError::HashFailure(e.to_string()))?
                    .to_string()
            }
            #[cfg(not(feature = "argon2"))]
            {
                return Err(PinHashError::UnsupportedScheme);
            }
        }
    };
    pin.zeroize();
    Ok(out)
}

pub fn verify_pin(candidate: &mut String, stored: &str) -> bool {
    let scheme = if stored.starts_with("$6$") {
        Scheme::Sha512Crypt
    } else if stored.starts_with("$argon2") {
        Scheme::Argon2id
    } else {
        scheme_from_env()
    };
    let ok = match scheme {
        Scheme::Sha512Crypt => {
            #[cfg(feature = "sha-crypt")]
            {
                sha512_check(candidate, stored).is_ok()
            }
            #[cfg(not(feature = "sha-crypt"))]
            {
                false
            }
        }
        Scheme::Argon2id => {
            #[cfg(feature = "argon2")]
            {
                if let Ok(ph) = PasswordHash::new(stored) {
                    Argon2::default()
                        .verify_password(candidate.as_bytes(), &ph)
                        .is_ok()
                } else {
                    false
                }
            }
            #[cfg(not(feature = "argon2"))]
            {
                false
            }
        }
    };
    candidate.zeroize();
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_pin() {
        let mut pin = String::from("1234");
        match hash_pin(&mut pin) {
            Ok(hash) => {
                let mut good = String::from("1234");
                assert!(verify_pin(&mut good, &hash));
                let mut bad = String::from("9999");
                assert!(!verify_pin(&mut bad, &hash));
            }
            Err(PinHashError::UnsupportedScheme) => {
                // Feature set provides neither hashing backend; skip.
                eprintln!("Skipping round_trip_pin: unsupported scheme");
            }
            Err(e) => panic!("hash: {e:?}"),
        }
    }
}
