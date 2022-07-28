use aws_sdk_dynamodb::model::{AttributeValue, Select};
use axum::body::HttpBody;
use axum::{http::StatusCode, response::IntoResponse, Json};
use http::header::HeaderMap;
use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use totp_rs::{Algorithm, TOTP};

use crate::db::DB_AWS;
use crate::eval_constants::{get_step_size_value, get_totp_size_value};
use crate::obj::KEY_MAP;
use crate::{
    obj::{User, VerifyUser},
    operation::{generate_secret, get_secret},
};
use qrcode_generator::QrCodeEcc;

async fn get_user_key(email: &String) -> Option<String> {
    let client = DB_AWS.get().await;

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

                let mut ans = None;

                let u = resp.items.unwrap();

                ans = Some(u[0].get("secret").unwrap().as_s().unwrap().to_owned());

                if ans.is_none() {
                    return None;
                }

                return ans;
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

pub async fn verification(Json(payload): Json<VerifyUser>) -> impl IntoResponse {
    tracing::log::info!("verfication of user");

    if payload.is_valid() {
        match get_user_key(&payload.email).await {
            Some(secret) => {
                println!(" payload:{payload:?}");

                let server_token = match get_secret(&secret) {
                    Ok(token) => token,
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, "bad format".to_string());
                    }
                };

                println!("server_tok:{server_token}");

                if server_token == payload.token {
                    return (StatusCode::ACCEPTED, format!("welcome : {}", payload.email));
                }

                return (StatusCode::NOT_FOUND, "invalid user".to_string());
            }
            None => {
                return (StatusCode::NOT_FOUND, "invalid user".to_string());
            }
        }
    }
    return (StatusCode::BAD_REQUEST, "bad format".to_string());
}

async fn discover_user(email: &String) -> Option<()> {
    let email_av = AttributeValue::S(email.to_owned());
    let key = "user_email".to_string();

    let client = DB_AWS.get().await;

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

async fn insert_user(email: &String, secret: &String) -> Option<()> {
    let email_av = AttributeValue::S(email.to_owned());
    let secret_av = AttributeValue::S(secret.to_owned());

    let client = DB_AWS.get().await;

    let table_name: String = KEY_MAP
        .get(&"auth-table".to_string())
        .unwrap_or(&"auth-totp".to_string())
        .to_owned();

    let request = client
        .put_item()
        .table_name(table_name)
        .item("user_email", email_av)
        .item("secret", secret_av);

    match request.send().await {
        Ok(output) => {
            if output.attributes.is_none() {
                println!("insertion succesfull");
                return Some(());
            } else {
                println!("value already present");
                return None;
            }
        }
        Err(_) => {
            println!(" Insertion  invalid");
            return None;
        }
    };
}

pub async fn register_user(Json(payload): Json<User>) -> impl IntoResponse {
    tracing::log::info!("registration of token");
    let mut hm = HeaderMap::new();

    hm.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

    if payload.is_valid() {
        //acquire the secret the key for the token registeration and insertion in database
        let secret_key = generate_secret();
        println!("secret_key: {secret_key} payload:{payload:?}");
        let user_presence = discover_user(&payload.email).await;

        if user_presence.is_some() {
            return (
                hm,
                "unauthorized insertion"
                    .to_string()
                    .chars()
                    .map(|x| x as u8)
                    .collect::<Vec<u8>>(),
            );
        }

        let db_state_update = insert_user(&payload.email, &secret_key).await;
        //perform the insertion in the database
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

    return (
        hm,
        "insertion invalid"
            .to_string()
            .chars()
            .map(|x| x as u8)
            .collect::<Vec<u8>>(),
    );
}
