use std::collections::HashMap;

use aws_sdk_dynamodb::model::{AttributeValue, Select};
use axum::{http::StatusCode, response::IntoResponse, Json};
use http::header::HeaderMap;
use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use serde_json::json;
use totp_rs::{Algorithm, TOTP};

use crate::db::DynamoDBClient;
use crate::eval_constants::{get_step_size_value, get_totp_size_value};
use crate::obj::{RegUser, KEY_MAP};
use crate::operation::decrypt_token;
use crate::{
    obj::{User, VerifyUser},
    operation::{generate_secret, get_secret},
};
use qrcode_generator::QrCodeEcc;

async fn get_user_key(email: &String, pwd: &String) -> Option<String> {
    let client = &DynamoDBClient.to_owned();

    let key = "user_email".to_string();
    let user_av = AttributeValue::S(email.to_owned());

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    match client
        .query()
        .table_name(table_name)
        .key_condition_expression("#key = :value".to_string())
        .expression_attribute_names("#key".to_string(), key)
        .expression_attribute_values(":value".to_string(), user_av)
        .select(Select::AllAttributes)
        .send()
        .await
    {
        Ok(resp) => {

            if resp.count > 0 {
                tracing::log::info!("User entry found in the table:");

                let u = resp.items.unwrap();

                let pwd = u[0].get("hash").unwrap().as_s().unwrap().to_owned();

                return Some(pwd);

            } else {
                println!("not found in the table");
                return None;
            }
        }
        Err(e) => {
            eprintln!("error -> {}", e);
            return None;
        }
    }
}

async fn get_user_secret(email: &String) -> Option<String> {
    let client = &DynamoDBClient.to_owned();

    let key = "user_email".to_string();
    let user_av = AttributeValue::S(email.to_owned());

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    match client
        .query()
        .table_name(table_name)
        .key_condition_expression("#key = :value".to_string())
        .expression_attribute_names("#key".to_string(), key)
        .expression_attribute_values(":value".to_string(), user_av)
        .select(Select::AllAttributes)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.count > 0 {
                tracing::log::info!("User entry found in the table:");

                let u = resp.items.unwrap();

                let ans = u[0].get("secret").unwrap().as_s().unwrap().to_owned();

                return Some(ans);

            } else {
                println!("not found in the table");
                return None;
            }
        }
        Err(e) => {
            eprintln!("error -> {}", e);
            return None;
        }
    }
}

async fn get_user_name(email: &String) -> Option<String> {
    let client = &DynamoDBClient.to_owned();

    let key = "user_email".to_string();
    let user_av = AttributeValue::S(email.to_owned());

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    match client
        .query()
        .table_name(table_name)
        .key_condition_expression("#key = :value".to_string())
        .expression_attribute_names("#key".to_string(), key)
        .expression_attribute_values(":value".to_string(), user_av)
        .select(Select::AllAttributes)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.count > 0 {
                tracing::log::info!("User entry found in the table:");

                let u = resp.items.unwrap();

                let ans = u[0].get("user_name").unwrap().as_s().unwrap().to_owned();

                if ans.is_empty() {
                    return None;
                }

                return Some(ans);

            } else {
                tracing::log::warn!("not found in the table");
                return None;
            }
        }
        Err(e) => {
            tracing::log::error!("error -> {}", e);
            return None;
        }
    }
}

async fn discover_user(email: &String, user: &String) -> Option<()> {

    let email_av = AttributeValue::S(email.to_owned());
    // let user_av2 = AttributeValue::S(user.to_owned());
    let key = "user_email".to_string();
    // let key2 = "user_name".to_string();
    let client = &DynamoDBClient.to_owned();

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    match client
        .query()
        .table_name(table_name)
        .key_condition_expression("#key = :value".to_string())
        .expression_attribute_names("#key".to_string(), key)
        .expression_attribute_values(":value".to_string(), email_av)
        .select(Select::AllAttributes)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.count > 0 {
                tracing::log::info!("User entry is present in the table");
                return Some(());
            } else {
                tracing::log::error!("User entry not found");
                return None;
            }
        }
        Err(e) => {
            tracing::log::info!("error querying the user record: {e}");
            return None;
        }
    }
}

async fn insert_user(email: &String, secret: &String, username: &String, h: &String) -> Option<()> {

    let email_av = AttributeValue::S(email.to_owned());
    let secret_av = AttributeValue::S(secret.to_owned());
    let username_av = AttributeValue::S(username.to_owned());
    let hash = AttributeValue::S(h.to_owned());

    let client = &DynamoDBClient.to_owned();

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    let request = client
        .put_item()
        .table_name(table_name)
        .item("user_email", email_av)
        .item("secret", secret_av)
        .item("user_name", username_av)
        .item("hash", hash);

    match request.send().await {
        Ok(output) => {
            if output.attributes.is_none() {
                tracing::log::info!(" Insertion succesfull");
                return Some(());
            } else {
                tracing::log::warn!(" Value already present");
                return None;
            }
        }
        Err(_) => {
            tracing::log::error!(" Insertion  invalid");
            return None;
        }
    };
}

/*
The function declared below is the route for performing the operation regarding registering the user
to the with the fields
*/

//  This route accepts JSON of type payload to be decoded as a parameter
pub async fn register_user(Json(payload): Json<RegUser>) -> impl IntoResponse {

    tracing::log::info!(" Registration of token");
    let mut hm = HeaderMap::new(); //create a new header map for generating the respective headers

    hm.insert(CONTENT_TYPE, "text/plain".parse().unwrap()); //set a default header type

    if payload.is_valid() {
        //use a provided method for check wheather the contents are in valid  shape or not
        // in the payload type

        //acquire the secret the key for the token registeration and insertion in database
        let secret_key = generate_secret();

        let user_presence = discover_user(&payload.email, &payload.username).await;
        //check wheather the user is already present in database or not and return a option type corresponding to it

        if user_presence.is_some() {
            // If user is found in the database
            //return the tuple consisting of HeaderMap & the message as the field to it
            return (
                hm,
                "unauthorized insertion"
                    .to_string()
                    .chars()
                    .map(|x| x as u8)
                    .collect::<Vec<u8>>(),
            );
        }
        /*
        If the above condition is not valid then continue with the insertion of the user credentials in the database
        */

        let hash = crate::operation::get_hash(&payload.passwd);
        //compute the hashing based upon the passwd field
        let db_state_update =
            insert_user(&payload.email, &secret_key, &payload.username, &hash).await;
        //perform the insertion in the database using the credentials passed

        match db_state_update {
            None => {
                //return the error if value is already found
                return (
                    hm,
                    "insertion invalid"
                        .to_string()
                        .chars()
                        .map(|x| x as u8)
                        .collect::<Vec<u8>>(),
                );
            }
            Some(_) => {
                //otherwise insert the value in DB
                tracing::log::info!("insertion succesfull");
            }
        }
        // If the above condition was passed then continue with the generation of the token

        let totp = match TOTP::new(
            Algorithm::SHA1,
            get_totp_size_value() as usize,
            0,
            get_step_size_value(),
            secret_key.clone(),
            Some("Rust server".to_string()),
            payload.email,
        ) {
            Ok(totp) => totp,
            Err(_) => {
                return (
                    hm,
                    "insertion invalid"
                        .to_string()
                        .chars()
                        .map(|x| x as u8)
                        .collect::<Vec<u8>>(),
                );
            }
        };

        //get the QR in the form of vec<u8>
        let result: Vec<u8> =
            qrcode_generator::to_png_to_vec(totp.get_url(), QrCodeEcc::Low, 240).unwrap();

        hm.insert(CONTENT_TYPE, "image/png ; base64".parse().unwrap());
        //hm.insert(CONTENT_ENCODING, "base64".parse().unwrap());
        hm.insert(
            CONTENT_DISPOSITION,
            "attachment; filename=\"qr.png\"".parse().unwrap(),
        );

        return (hm, result);
    }

    tracing::log::info!("payload not valid");

    return (
        hm,
        "insertion invalid"
            .to_string()
            .chars()
            .map(|x| x as u8)
            .collect::<Vec<u8>>(),
    );
}

pub async fn authentication(Json(payload): Json<User>) -> impl IntoResponse {
    let mut hm = HeaderMap::new();
    hm.insert(CONTENT_TYPE, "application/json".parse().unwrap());

    if payload.is_valid() {

        let aux_key  = &"some random key".to_string();

        let encrypt_key = KEY_MAP
            .get(&"symmetric-token-key".to_string())
            .unwrap_or(aux_key);

        let val = decrypt_token(&payload.authtoken, encrypt_key).unwrap();

        let hm1: HashMap<String, String> = serde_json::from_str(val.as_str()).unwrap();

        let prev_utc = hm1.get(&"utc".to_string()).unwrap().as_str();
        let prev_user = hm1.get(&"user".to_string()).unwrap().as_str();

        if crate::operation::validate_token(prev_utc, 7) && (prev_user == payload.email.as_str()) {

            let body_content = serde_json::json!({
                "user": hm1["user"].to_owned(),
                "session_id": hm1["session uid"].to_owned(),
                "date": chrono::Utc::now().to_string(),
                "username": get_user_name(&payload.email.to_owned()).await.unwrap()
            });

            return (hm, Json(body_content));
        }

        return (
            hm,
            Json(serde_json::json!({"Invalid user":  payload.email.to_owned()})),
        );
    }

    return (
        hm,
        Json(serde_json::json!({"Invalid user":  payload.email.to_owned()})),
    );
}

pub async fn verification(Json(payload): Json<VerifyUser>) -> impl IntoResponse {
    tracing::log::info!("verfication of user");

    let error_json = Json(json!({"Invalid user": &payload.email}));

    if payload.is_valid() {
        match get_user_key(&payload.email, &payload.passwd).await {
            Some(hashed_passwd) => {
                /*
                extract the hash of the passwd against the user
                */
                let valid = match bcrypt::verify(&payload.passwd, &hashed_passwd.as_str()) {
                    Ok(b) => b,
                    Err(e) => {
                        return (StatusCode::NOT_FOUND, error_json);
                    }
                };

                if valid {
                    let session_uid = uuid::Uuid::new_v4().hyphenated().to_string();
                    let utc = chrono::Utc::now();

                    let data = serde_json::json!({
                        "session uid": session_uid,
                        "email": &payload.email.to_owned(), 
                        "utc": utc,
                    })
                    .to_string();

                    let (aux_key, aux_nonce) = (&"some random key".to_string(), &"some random key".to_string()); 

                    let encrypt_key = KEY_MAP
                    .get(&"symmetric-token-totp-key".to_string())
                    .unwrap_or(aux_key);
                    
                    let nonce_key = KEY_MAP
                    .get(&"nonce-totp-token".to_string())
                    .unwrap_or(aux_nonce);


                    let tok = crate::operation::generate_token(&data, encrypt_key, nonce_key).unwrap();
                    let json = Json(serde_json::json!({ "token": tok }));

                    return (StatusCode::ACCEPTED, json);
                }

                return (StatusCode::NOT_FOUND, error_json);
            }
            None => {
                return (StatusCode::NOT_FOUND, error_json);
            }
        }
    }
    return (StatusCode::BAD_REQUEST, error_json);
}

pub async fn otp_verification(Json(urlValue): Json<HashMap<String, String>>) -> impl IntoResponse {

    let mut hm = HeaderMap::new(); //create a new header map for generating the respective headers
    hm.insert(CONTENT_TYPE, "application/json".parse().unwrap()); //set a default header type

    let totp = urlValue.get(&"totp".to_string()).unwrap();
    let token = urlValue.get(&"token".to_string()).unwrap();
    let user_email = urlValue.get(&"email".to_string()).unwrap();

    
    let error_json = Json(json!({"Invalid user": &user_email}));


    if !totp.is_empty() && !token.is_empty() && !user_email.is_empty(){

        let aux_key = &"some random key".to_string();
        let encrypt_key = KEY_MAP
                    .get(&"symmetric-token-totp-key".to_string())
                    .unwrap_or(aux_key);


        let decrypted_val = decrypt_token(&token, encrypt_key).unwrap();
        let cred_map: HashMap<String, String> = serde_json::from_str(decrypted_val.as_str()).unwrap();

        let prev_utc = cred_map.get(&"utc".to_string()).unwrap().as_str();
        let prev_user = cred_map.get(&"email".to_string()).unwrap().as_str();

        if !(crate::operation::validate_token(prev_utc, 3) && (prev_user == user_email.as_str())) {

            return (hm, error_json);

        }
        
        let secret = get_user_secret(&user_email).await.unwrap();
        let server_token = match get_secret(&secret) {
            Ok(token) => token,
            Err(_) => {
                return (hm, error_json);
            }
        };

        if &server_token == totp {
            
            let (aux_key, aux_nonce) = (&"some random key".to_string(), &"some random key".to_string()); 

            let encrypt_key = KEY_MAP
            .get(&"symmetric-token-key".to_string())
            .unwrap_or(aux_key);
            
            let nonce_key = KEY_MAP
            .get(&"nonce-token".to_string())
            .unwrap_or(aux_nonce);

            
            let body_content = serde_json::json!({
                "user": cred_map["email"].to_owned(),
                "session uid": cred_map["session uid"].to_owned(),
                "utc": chrono::Utc::now().to_string(),
                "username": get_user_name(&user_email.to_owned()).await.unwrap()
            }).to_string();

            let tok = crate::operation::generate_token(&body_content, encrypt_key, nonce_key).unwrap();
            let json = Json(serde_json::json!({ "session token": tok }));
            
            return (hm, json);
        }
    }

    return (hm, error_json);
}
