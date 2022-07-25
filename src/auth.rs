use axum::{http::StatusCode, response::IntoResponse, Json};
use http::header::{HeaderMap, CONTENT_ENCODING};
use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use totp_rs::{Algorithm, TOTP};

use crate::eval_constants::{get_step_size_value, get_totp_size_value};
use crate::{
    db::DB,
    obj::{User, VerifyUser},
    operation::{generate_secret, get_secret},
};
use qrcode_generator::QrCodeEcc;

pub async fn verification(Json(payload): Json<VerifyUser>) -> impl IntoResponse {
    tracing::log::info!("verfication of user");

    unsafe {
        println!("hm: {DB:?} pay:{payload:?}");
    }

    if payload.is_valid() {
        unsafe {
            match DB.get(&payload.email) {
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
    }
    return (StatusCode::BAD_REQUEST, "bad format".to_string());
}

pub async fn register_user(Json(payload): Json<User>) -> impl IntoResponse {
    tracing::log::info!("registration of token");
    let mut hm = HeaderMap::new();

    hm.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

    if payload.is_valid() {
        //acquire the secret the key for the token registeration and insertion in database
        let secret_key = generate_secret();
        println!("secret_key: {secret_key} payload:{payload:?}");

        unsafe {
            //perform the insertion in the database
            match DB.get(&payload.email) {
                Some(t) => {
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
                None => {
                    //otherwise insert the value in DB
                    DB.insert(payload.email.clone(), secret_key.clone());
                }
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
            Err(e) => {
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
