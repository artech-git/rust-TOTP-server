use axum::{
    http::{header::CONTENT_TYPE, HeaderMap},
    response::IntoResponse,
    Extension, Json,
};
use totp_rs::TOTP;

use crate::{
    eval_constants::{get_step_size_value, get_totp_size_value},
    handles::utils::{discover_user, insert_user},
    obj::User,
    operation::generate_secret,
};

use sqlx::Pool;
use sqlx::Postgres;

pub async fn register_user(
    Extension(db_handle): Extension<Pool<Postgres>>,
    Json(payload): Json<User>,
) -> impl IntoResponse {
    tracing::log::info!("registration of token");
    let mut hm = HeaderMap::new();

    hm.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

    if payload.is_valid() {
        // acquire the secret the key for the token registeration and insertion in database
        let secret_key = generate_secret();
        println!("secret_key: {secret_key} payload:{payload:?}");
        let user_presence = discover_user(&db_handle, &payload.email).await;

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

        let db_state_update = insert_user(&db_handle, &payload.email, &secret_key).await;
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
            totp_rs::Algorithm::SHA1,
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
            qrcode_generator::to_png_to_vec(totp.get_url(), qrcode_generator::QrCodeEcc::Low, 240)
                .unwrap();

        hm.insert(CONTENT_TYPE, "image/png ; base64".parse().unwrap());
        //hm.insert(CONTENT_ENCODING, "base64".parse().unwrap());
        hm.insert(
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"qr.png\"".parse().unwrap(),
        );

        return (hm, result);
    }

    return (hm, "insertion invalid".as_bytes().to_vec());
}
