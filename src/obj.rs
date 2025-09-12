use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

//==================================================================================================================

static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap());

//==================================================================================================================
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyUser {
    pub email: String,
    pub token: String,
}

impl VerifyUser {
    pub fn is_valid(&self, totp_size: u32) -> bool {
        if self.email.is_empty() || self.token.is_empty() {
            return false;
        }

        if self.token.chars().count() != (totp_size as usize) {
            return false;
        }

        EMAIL_REGEX.is_match(self.email.as_str())
    }
}
//==================================================================================================================
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub email: String,
}

impl User {
    pub fn is_valid(&self) -> bool {
        if self.email.is_empty() {
            return false;
        }

        let res = EMAIL_REGEX.is_match(&self.email);
        println!("called validation on email: {res}");
        return res;
    }
}
//==================================================================================================================
