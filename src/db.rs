
use aws_sdk_dynamodb::{Client, Endpoint, Region};
use aws_types::Credentials;
use http::Uri;
use once_cell::sync::Lazy;

use crate::{obj::KEY_MAP,};

// #[allow(non_camel_case_types)]
// pub trait DB_Types { 
//     fn insert_db_table(query: String) -> Result<(), BackendError<>>; 
//     fn retrieve_db_table() -> Result<Option<Value>, BackendError<>>; 
// }

#[allow(non_camel_case_types)]
pub trait DB_Operation {
    fn get_user_key(&self, email: &String, pwd: &String) -> Option<String>; 
    fn get_user_secret(&self, email: &String) -> Option<String>; 
    fn get_user_name(&self, email: &String) -> Option<String>; 
    fn discover_user(&self, email: &String, user: &String) -> Option<()>; 
    fn insert_user(&self, email: &String, secret: &String, username: &String, hash: &String) -> Option<()>; 
}

// #[allow(non_camel_case_types)]
// #[derive(Debug)]
// pub struct DynamoDBClient(Client); 

// impl DynamoDBClient {

//     fn new() -> Self {
//         let region = KEY_MAP
//             .get(&"aws-region".to_string())
//             .unwrap_or(&"ap-south-1".to_string())
//             .to_owned();
    
//         let url = KEY_MAP
//             .get(&"aws-region-url".to_string())
//             .unwrap_or(&format!("https://dynamodb.{}.amazonaws.com/", region))
//             .to_owned()
//             .parse::<Uri>()
//             .unwrap();
    
//         let db_key = match KEY_MAP.get(&"db-access-key".to_string()) {
//             Some(v) => {
//                 tracing::log::info!("access key present");
//                 v
//             }
//             None => {
//                 tracing::log::warn!("access key is not present");
//                 panic!();
//             }
//         };
    
//         let db_sec = match KEY_MAP.get(&"db-secret-access-key".to_string()) {
//             Some(v) => {
//                 tracing::log::info!("db secret key present");
//                 v
//             }
//             None => {
//                 tracing::log::warn!("secret key is not present");
//                 panic!();
//             }
//         };
    
//         let creds = Credentials::from_keys(db_key, db_sec, None);
    
//         let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::new()
//             .credentials_provider(creds)
//             .region(Region::new(region))
//             .endpoint_resolver(Endpoint::immutable(url))
//             .build();
    
//         let client = Client::from_conf(dynamodb_local_config);
    
//         return client;
//     }

// }

// impl DB_Operation for DynamoDBClient {

// }

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub struct NormalDBClient(sled::Db); 
// key: Email
// Value: username, secret, passwd_hash, auth_token

impl std::ops::Deref for NormalDBClient { 
    
    type Target = sled::Db;
    
    fn deref(&self) -> &Self::Target { 
        &self.0
    }
}

impl std::ops::DerefMut for NormalDBClient { 

    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NormalDBClient {
    
    pub fn new(tree_path: String) -> Self {

        let config = sled::Config::new()
            .path(tree_path.as_ref())
            .mode(sled::Mode::HighThroughput)
            .create_new(true)
            .cache_capacity(10_00_00);

        let db_res = config.open(); 

        if let Ok(val) = db_res { 
            Self(val)
        }
        else if let Err(e) = db_res {
            panic!("Error: opening database file at /'{tree_path}/' - Error Message: {e}");
        }
    }

}

impl Drop for NormalDBClient {
    fn drop(&mut self) {
        if let Err(e) = self.save_on_disk() { 
            panic!("Error saving file on the disk: {e}"); 
        } 
    }
}

impl DB_Operation for NormalDBClient {

    //TODO: convert the native unwrap of the sled::Db to result type, for each method 

    fn get_user_key(&self, email: &String, pwd: &String) -> Option<String> { 
        
        if let Some(val) = self.get(email).unwrap() {
            Some(val[2].to_owned())
        }
        return None;
    }

    fn get_user_secret(&self, email: &String) -> Option<String> {
        if let Some(val) = self.get(email).unwrap() {
            Some(val[1].to_owned())
        }
        return None; 
    }

    fn get_user_name(&self, email: &String) -> Option<String> {
        if let Some(val) = self.get(email).unwrap() {
            Some(val[0])
        }
        return None;
    }

    fn discover_user(&self, email: &String, user: &String) -> Option<()> {
        if let Some(val) = self.get(email).unwrap() {
            Some(())
        }
        return None;
    }

    fn insert_user(&self, email: &String, secret: &String, username: &String, hash: &String) -> Option<()> {
        
        let mut value = (username.to_owned(),secret.to_owned(),hash.to_owned(),());
        let insert_result = self.insert(email.as_ref(), value.into()).unwrap();

        let return_value = match insert_result {
            Some(val) => Some(()),
            None => None
        };

        return return_value;
    }
}

