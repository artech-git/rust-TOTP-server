use crate::error::{Error, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::time::SystemTime;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};

//return a random set of string which we can use to create a QR code
pub fn generate_secret(key_size: usize) -> String {
    let rand_str: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(key_size)
        .map(char::from)
        .collect();

    rand_str
}

//create the on time based OTP out of the given secret
pub fn get_secret(input: &str, key_size: usize, totp_size: u32) -> Result<String> {
    let length = input.trim().chars().count();

    if length != key_size {
        tracing::log::error!("Invalid TOTP secret key size ");
        return Err(Error::Paseto); // Using Paseto error for now, will create a better error later
    }

    // The number of seconds since the Unix Epoch, used to calcuate a TOTP secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::Paseto)? // Using Paseto error for now
        .as_secs();

    let base = input.as_bytes().to_vec();

    // Calculate a 6 digit TOTP two-factor authentication code.
    let token = totp_custom::<Sha1>(
        // Calculate a new code every 30 seconds.
        DEFAULT_STEP,
        // Calculate a 6 digit code.
        totp_size,
        // Convert the secret into bytes using base32::decode().
        &base,
        // Seconds since the Unix Epoch.
        seconds,
    );

    Ok(token)
}

pub fn get_hash(client_secret: &str) -> Result<String> {
    let hash = bcrypt::hash(client_secret, 5)?;
    Ok(hash)
}

pub fn generate_token(data: &str, encrypt_key: &str, nonce_key: &str) -> Result<String> {
    use rusty_paseto::core::*;

    let key = PasetoSymmetricKey::<V4, Local>::from(
        Key::<32>::try_from(encrypt_key).map_err(|_| Error::Paseto)?,
    );

    let nonce = Key::<32>::try_from(nonce_key).map_err(|_| Error::Paseto)?;
    let paseto_nonce = PasetoNonce::<V4, Local>::from(&nonce);

    let payload = Payload::from(data);

    let token = Paseto::<V4, Local>::builder()
        .set_payload(payload)
        .try_encrypt(&key, &paseto_nonce)
        .map_err(|_| Error::Paseto)?;

    Ok(token.to_string())
}

pub fn validate_token(prev_utc: &str, mins: u8) -> Result<bool> {
    let prev_time = chrono::DateTime::parse_from_rfc3339(prev_utc)?;

    let duration = chrono::Utc::now().signed_duration_since(prev_time);

    let time = 60 * (mins as i64);

    if duration < chrono::Duration::seconds(time) {
        return Ok(true);
    }
    Ok(false)
}

pub fn decrypt_token(token: &str, encrypt_key: &str) -> Result<String> {
    let get_key =
        rusty_paseto::prelude::Key::<32>::try_from(encrypt_key).map_err(|_| Error::Paseto)?;

    let key = rusty_paseto::prelude::PasetoSymmetricKey::<
        rusty_paseto::prelude::V4,
        rusty_paseto::prelude::Local,
    >::from(get_key);

    let val = rusty_paseto::prelude::Paseto::<
        rusty_paseto::prelude::V4,
        rusty_paseto::prelude::Local,
    >::try_decrypt(token, &key, None, None)
    .map_err(|_| Error::Paseto)?;

    Ok(val)
}
