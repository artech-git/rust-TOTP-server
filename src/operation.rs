use koibumi_base32 as base32;
use std::io::{self, Write};
use std::time::SystemTime;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};



//return a random set of string which we can use to create a QR code
pub fn generate_secret() -> String {
    "abcdefghijkl".to_string()
} 

//create the on time based OTP out of the given secret 
pub fn get_secret(input: &String) -> Result<String,()> {
    
        let length = input.trim().len();

        // if length != 16 && length != 26 && length != 32 {
        //     tracing::log::error!("Invalid TOTP secret, must be 16, 26 or 32 characters.");
        //     return Err(());            
        // }

        // The number of seconds since the Unix Epoch, used to calcuate a TOTP secret.
        let seconds: u64 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Calculate a 6 digit TOTP two-factor authentication code.
        let token = 
            totp_custom::<Sha1>(
                // Calculate a new code every 30 seconds.
                DEFAULT_STEP,
                // Calculate a 6 digit code.
                6,
                // Convert the secret into bytes using base32::decode().
                &base32::decode(&input.trim().to_lowercase()).unwrap(),
                // Seconds since the Unix Epoch.
                seconds,
            );

        return Ok(token);
}