use std::collections::HashMap;

use config::Config;
use once_cell::sync::{Lazy, OnceCell};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::eval_constants::get_totp_size_value;
//==================================================================================================================

pub const FILE_PATH: &str = "./settings.toml";

pub static KEY_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let settings = match Config::builder()
        // Add in `./Settings.toml`
        .add_source(config::File::with_name(FILE_PATH))
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(config::Environment::with_prefix("APP"))
        .build()
    {
        Ok(v) => {
            tracing::log::info!("settings.toml read");
            v
        }
        Err(e) => {
            tracing::log::error!("cannot open the file: {}", e);
            panic!();
        }
    };

    let hm = match settings.try_deserialize::<HashMap<String, String>>() {
        Ok(v) => {
            tracing::log::info!("deserialization succesfull");
            v
        }
        Err(e) => {
            tracing::log::error!("error deserialization of values: {}", e);
            panic!();
        }
    };

    return hm;
});

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

        if self.token.chars().count() != (get_totp_size_value() as usize) {
            return false;
        }
        let mut regex = OnceCell::new();
        //todo evaluate the email constrain too
        regex.get_or_init(
            Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap(),
        );

        regex.is_match(self.email.as_str())
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

        let mut regex = OnceCell::new();

        //todo evaluate the email constrain too
        regex.get_or_init(
            Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap(),
        );

        let res = regex.is_match(&self.email);
        println!("called validation on email: {res}");
        return res;
    }
}
//==================================================================================================================
