use std::{str::FromStr, time::SystemTime};
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};

use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::{
    eval_constants::{get_key_size_value, get_totp_size_value},
    obj::KEY_MAP,
};

//return a random set of string which we can use to create a QR code
pub fn generate_secret() -> String {
    // const STR_LEN: usize = 10;
    let rand_str = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(get_key_size_value())
        .map(char::from)
        .collect();

    rand_str
}

//create the on time based OTP out of the given secret
pub fn get_secret(input: &String) -> Result<String, ()> {
    let length = input.trim().chars().count();

    if length != (get_key_size_value()) {
        tracing::log::error!("Invalid TOTP secret key size ");
        return Err(());
    }

    // The number of seconds since the Unix Epoch, used to calcuate a TOTP secret.
    let seconds: u64 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let base = input.as_bytes().to_vec();

    // Calculate a 6 digit TOTP two-factor authentication code.
    let token = totp_custom::<Sha1>(
        // Calculate a new code every 30 seconds.
        DEFAULT_STEP,
        // Calculate a 6 digit code.
        get_totp_size_value(),
        // Convert the secret into bytes using base32::decode().
        &base,
        // Seconds since the Unix Epoch.
        seconds,
    );

    return Ok(token);
}

pub fn get_hash(client_secret: &String) -> String {
    let hash = match bcrypt::hash(client_secret.as_ref() as &str, 5) {
        Ok(f) => f,
        Err(e) => {
            tracing::log::error!("error in creating a hash of client secret: {}", e);
            panic!();
        }
    };

    hash
}

pub fn generate_token(
    data: &String,
    encrypt_key: &String,
    nonce_key: &String,
) -> Result<String, ()> {
    use rusty_paseto::core::*;

    let key =
        PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from(encrypt_key.as_str()).unwrap());

    let nonce = Key::<32>::try_from(nonce_key.as_str()).unwrap();
    // let nonce = Key::<32>::try_new_random().unwrap();
    let paseto_nonce = PasetoNonce::<V4, Local>::from(&nonce);

    let payload = Payload::from(data.as_str());

    let token = match Paseto::<V4, Local>::builder()
        .set_payload(payload)
        .try_encrypt(&key, &paseto_nonce)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!(" generate token error: {e}");
            return Err(());
        }
    };

    return Ok(token.to_string());
}

pub fn validate_token(prev_utc: &str, mins: u8) -> bool {
    let prev_time = chrono::DateTime::from_str(prev_utc).unwrap();

    let duration = chrono::Utc::now() - prev_time;

    let time = 60 * (mins as i64);

    if duration < chrono::Duration::seconds(time) {
        return true;
    }
    return false;
}

pub fn decrypt_token(token: &String, encrypt_key: &String) -> Result<String, ()> {
    let get_key = match rusty_paseto::prelude::Key::<32>::try_from(encrypt_key.as_str()) {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!(" key generation error : {e}");
            return Err(());
        }
    };

    let key = rusty_paseto::prelude::PasetoSymmetricKey::<
        rusty_paseto::prelude::V4,
        rusty_paseto::prelude::Local,
    >::from(get_key);

    let val = match rusty_paseto::prelude::Paseto::<
        rusty_paseto::prelude::V4,
        rusty_paseto::prelude::Local,
    >::try_decrypt(token, &key, None, None)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!(" decryption error: {e} ");
            return Err(());
        }
    };

    return Ok(val);
}
