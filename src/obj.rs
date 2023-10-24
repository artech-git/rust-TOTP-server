use std::collections::HashMap;

use config::Config;
use once_cell::sync::Lazy;
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
    pub passwd: String,
}

impl VerifyUser {
    #[allow(non_snake_case)]
    pub fn is_valid(&self) -> bool {
        if self.email.is_empty() || self.token.is_empty() || self.passwd.is_empty() {
            return false;
        }

        if self.token.chars().count() != (get_totp_size_value() as usize) {
            return false;
        }
        //todo evaluate the email constrain too
        let RE = Lazy::new( || 
            Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
            .unwrap()
        );
        

        (*RE).is_match(self.email.as_str())
    }
}
//==================================================================================================================
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub authtoken: String,
}

impl User {
    #[allow(non_snake_case)]
    pub fn is_valid(&self) -> bool {
        if self.email.is_empty() || self.authtoken.is_empty() {
            return false;
        }

        //todo evaluate the email constrain too
        let RE = Lazy::new( || 
            Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
            .unwrap()
        );
        
        let res = (*RE).is_match(&self.email);
        // println!("called validation on email: {res}");
        return res;
    }
}
//==================================================================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct RegUser {
    pub username: String,
    pub email: String,
    pub passwd: String,
}

impl RegUser {
    
    #[allow(non_snake_case)]
    pub fn is_valid(&self) -> bool {
        if self.email.is_empty() {
            return false;
        }

        //todo evaluate the email constrain too
        
        //todo regex validation syntax not supported for email and username find new regex for the same
        // static ref UE: Regex = Regex::new(r"^(?=[a-zA-Z0-9._]{8,20}$)(?!.*[_.]{2})[^_.].*[^_.]$").unwrap();
        // let RE = Lazy::new( || Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").unwrap());
        // static ref PS: Regex = Regex::new(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&'])[^ ]{8,}$").unwrap();

        // let res1 = (*UE).is_match(&self.email);
        let res1 = true;
        // let res2 = (*RE).is_match(&self.passwd);
        let res2 = true;
        // let res3 = (*PS).is_match(&self.username);
        let res3 = true;

        return res1 && res2 && res3;
    }

}
//==================================================================================================================
