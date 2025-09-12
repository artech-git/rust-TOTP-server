use crate::{
    config::Config,
    db::{Db, DbUser},
    error::{Error, Result},
    obj::{User, VerifyUser},
    operation::{generate_secret, get_secret},
};
use axum::{
    extract::Extension,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use http::header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_TYPE};
use qrcode_generator::QrCodeEcc;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};

pub async fn verification(
    Extension(db): Extension<Arc<Db>>,
    Extension(config): Extension<Arc<Config>>,
    Json(payload): Json<VerifyUser>,
) -> Result<impl IntoResponse> {
    tracing::log::info!("verification of user");

    if !payload.is_valid(config.totp_size) {
        return Err(Error::DbRecordNotFound);
    }

    let secret = db
        .get_user_secret(&config.auth_table, &payload.email)
        .await?;

    if let Some(secret) = secret {
        let server_token = get_secret(&secret, config.key_size, config.totp_size)?;
        if server_token == payload.token {
            return Ok((StatusCode::ACCEPTED, format!("welcome : {}", payload.email)));
        }
    }

    Err(Error::DbRecordNotFound)
}

pub async fn register_user(
    Extension(db): Extension<Arc<Db>>,
    Extension(config): Extension<Arc<Config>>,
    Json(payload): Json<User>,
) -> Result<impl IntoResponse> {
    tracing::log::info!("registration of token");

    if !payload.is_valid() {
        return Err(Error::DbRecordNotFound);
    }

    let user_presence = db
        .get_user_secret(&config.auth_table, &payload.email)
        .await?;

    if user_presence.is_some() {
        return Err(Error::DbRecordNotFound);
    }

    let secret_key = generate_secret(config.key_size);

    let db_user = DbUser {
        email: payload.email.clone(),
        secret: secret_key.clone(),
    };

    db.insert_user(&config.auth_table, &db_user).await?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        config.totp_size as usize,
        0,
        config.step_size,
        secret_key.clone(),
        Some("Rust server".to_string()),
        payload.email,
    )
    .map_err(|_| Error::TotpError)?;

    let result: Vec<u8> = qrcode_generator::to_png_to_vec(totp.get_url(), QrCodeEcc::Low, 240)?;

    let mut hm = HeaderMap::new();
    hm.insert(CONTENT_TYPE, "image/png ; base64".parse()?);
    hm.insert(
        CONTENT_DISPOSITION,
        "attachment; filename=\"qr.png\"".parse()?,
    );

    Ok((hm, result))
}
