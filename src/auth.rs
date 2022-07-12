use axum::{Json, http::{StatusCode, Uri, header}, response::IntoResponse};
use serde_json; 
use serde::{Serialize, Deserialize};
use tokio::select;
use regex::Regex;

use axum::body::StreamBody;

use http::{response::Response, header::{CONTENT_DISPOSITION, CONTENT_TYPE}};
use http::header::HeaderMap;

use crate::{operation::{generate_secret, get_secret}, db::DB};
use qrcode_generator::QrCodeEcc;


pub async fn verification(Json(payload): Json<verifyUser>) -> impl IntoResponse  {

    tracing::log::info!("verfication of user");

    unsafe{ println!("hm: {DB:?}");}

    if payload.is_valid() {
        unsafe{
            match DB.get(&payload.email) {
                Some(secret) => {
                    println!(" payload:{payload:?}");
                    
                    let server_token =  match get_secret(&secret) {
                        Ok(token)  => token,
                        Err(_) => {
                            return (StatusCode::BAD_REQUEST, "bad format".to_string());
                        }
                    };
                    
                    println!("server_tok:{server_token}");

                    if server_token == payload.token {
                        return (StatusCode::ACCEPTED, format!("welcome : {}", payload.email));
                    }

                    return ((StatusCode::NOT_FOUND, "invalid user".to_string()));
                }
                None => {
                    return ((StatusCode::NOT_FOUND, "invalid user".to_string()));
                }
            }
        }
    }
    return ((StatusCode::BAD_REQUEST, "bad format".to_string()));
}

#[derive(Debug,Serialize,Deserialize)]
pub struct verifyUser {
    pub email: String,
    pub token: String
}

impl verifyUser {
    fn is_valid(&self) -> bool {
        // if self.email.is_empty() || self.token.is_empty(){
        //     return false;
        // }

        // if self.token.len() != 6 {
        //     return false;
        // }
        // return true;
        // lazy_static! {//todo evaluate the email constrain too
        //     static ref RE: Regex = Regex::new(r"/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/").unwrap();
        // }
        // RE.is_match(self.email.as_str())
        return true;
    }
}



pub async fn register_user(Json(payload): Json<User>) -> impl IntoResponse
{
    tracing::log::info!("registration of token");
    let mut hm = HeaderMap::new();
    
    hm.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
    
    if payload.is_valid() {
        
        //acquire the secret the key for the token registeration and insertion in database
        let secret_key = generate_secret();
        println!("secret_key: {secret_key} payload:{payload:?}");

        unsafe{
        //perform the insertion in the database 
            match DB.get(&payload.email) {
                Some(t) => {
                    // hm.insert(FOUND)
                    //return the error if value is already found
                    return (hm, "insertion invalid".chars().map(|v| v as u8 ).collect::<Vec<u8>>());
                } 
                None => {
                    //otherwise insert the value in DB
                    DB.insert(payload.email.clone() , secret_key.clone()); 
                }
            }
        }

        //get the QR in the form of vec
        let result: Vec<u8> = qrcode_generator::to_png_to_vec(secret_key, QrCodeEcc::Low, 540).unwrap();
                
        hm.insert(CONTENT_TYPE, "image/png; ; charset=utf-8".parse().unwrap());
        hm.insert(CONTENT_DISPOSITION, "attachment; filename=\"qr.png\"".parse().unwrap());
        
        return (hm, result);
    }

    return (hm, "insertion invalid".chars().map(|v| v as u8 ).collect::<Vec<u8>>());
}


async fn with_status() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("invalid mail format"))
}


#[derive(Debug,Serialize, Deserialize)]
pub struct User {
    pub email: String
}

impl User {
    fn is_valid(&self) -> bool {
        if self.email.is_empty() {
            return false;
        }

        // lazy_static! {//todo evaluate the email constrain too
        //     static ref RE: Regex = Regex::new(r"/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/").unwrap();
        // }
        // RE.is_match(&self.email)
        return true;
    }
}