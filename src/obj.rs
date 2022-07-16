use regex::Regex;
use serde::{Deserialize, Serialize};

//==================================================================================================================

pub const KEY_SIZE: usize = 8;
pub const TOTP_SIZE: u32 = 6;
pub const STEP_SIZE: u64 = 30;

//==================================================================================================================
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyUser {
    pub email: String,
    pub token: String,
}

impl VerifyUser {
    pub fn is_valid(&self) -> bool {
        if self.email.is_empty() || self.token.is_empty() {
            return false;
        }

        if self.token.chars().count() != (TOTP_SIZE as usize) {
            return false;
        }
        lazy_static! {//todo evaluate the email constrain too
            static ref RE: Regex = Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap();
        }

        RE.is_match(self.email.as_str())
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

        lazy_static! {//todo evaluate the email constrain too
            static ref RE: Regex = Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap();
        }

        let res = (*RE).is_match(&self.email);
        println!("called validation on email: {res}");
        return res;
    }
}
//==================================================================================================================
