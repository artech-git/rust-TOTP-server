use std::time::SystemTime;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};

use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::eval_constants::{get_key_size_value, get_totp_size_value};

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
