use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{error::ApiError, extract::AuthUser, metrics::auth_event, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub user_id: String,
    pub email: String,
    pub recovery_codes_remaining: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegenerateResponse {
    /// Fresh one-time recovery codes. All previous codes are now invalid.
    pub recovery_codes: Vec<String>,
}

/// Return the authenticated user's profile.
#[utoipa::path(
    get, path = "/api/v1/me", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Current user", body = MeResponse),
        (status = 401, description = "Missing or invalid session token", body = crate::error::ErrorBody),
    )
)]
pub async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<MeResponse>, ApiError> {
    // Confirm the account still exists (token could outlive a deletion).
    let record = state
        .store
        .get_user_by_id(&user.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let remaining = state.store.count_unused_recovery_codes(&record.id).await?;
    Ok(Json(MeResponse {
        user_id: record.id,
        email: record.email,
        recovery_codes_remaining: remaining,
    }))
}

/// Replace the authenticated user's recovery codes with a fresh set.
#[utoipa::path(
    post, path = "/api/v1/recovery/regenerate", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "New recovery codes", body = RegenerateResponse),
        (status = 401, description = "Missing or invalid session token", body = crate::error::ErrorBody),
    )
)]
pub async fn regenerate_recovery(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<RegenerateResponse>, ApiError> {
    let record = state
        .store
        .get_user_by_id(&user.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let codes = crate::recovery::generate_codes(state.cfg.security.recovery_code_count);
    let hashes = crate::routes::auth::hash_codes(&state, &codes).await?;
    state
        .store
        .replace_recovery_codes(&record.id, &hashes)
        .await?;

    auth_event("recovery_regenerate", "success");
    Ok(Json(RegenerateResponse {
        recovery_codes: codes,
    }))
}

/// Permanently delete the authenticated user and all their data.
#[utoipa::path(
    delete, path = "/api/v1/me", tag = "account",
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Account deleted"),
        (status = 401, description = "Missing or invalid session token", body = crate::error::ErrorBody),
    )
)]
pub async fn delete_me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<StatusCode, ApiError> {
    // Recovery codes cascade-delete via the foreign key.
    if state.store.delete_user(&user.user_id).await? {
        auth_event("account_delete", "success");
    }
    Ok(StatusCode::NO_CONTENT)
}
