use crate::handles::utils::get_user_key;
use crate::obj::VerifyUser;
use crate::operation::get_secret;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sqlx::{Pool, Postgres};

pub async fn verification(
    db_handle: Pool<Postgres>,
    Json(payload): Json<VerifyUser>,
) -> impl IntoResponse {
    tracing::log::info!("verfication of user");

    if payload.is_valid() {
        match get_user_key(&db_handle, &payload.email).await {
            Some(secret) => {
                println!(" payload: {payload:?}");

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
