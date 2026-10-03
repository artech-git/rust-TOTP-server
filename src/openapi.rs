use utoipa::{
    Modify, OpenApi,
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
};

use crate::routes::{account, auth, meta};

/// OpenAPI 3.1 definition served at `/api-docs/openapi.json` and rendered by
/// the Swagger UI at `/docs`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "TOTP Server API",
        version = env!("CARGO_PKG_VERSION"),
        description = "RFC 6238 time-based one-time-password 2FA server with recovery codes, \
                       PASETO sessions, replay protection, and rate limiting.",
        license(name = "MIT"),
    ),
    paths(
        auth::enroll,
        auth::confirm,
        auth::login,
        auth::login_recovery,
        account::me,
        account::regenerate_recovery,
        account::delete_me,
        meta::health,
    ),
    components(schemas(
        auth::EnrollRequest,
        auth::EnrollResponse,
        auth::ConfirmRequest,
        auth::ConfirmResponse,
        auth::LoginRequest,
        auth::RecoveryLoginRequest,
        auth::SessionResponse,
        account::MeResponse,
        account::RegenerateResponse,
        crate::error::ErrorBody,
    )),
    tags(
        (name = "enrollment", description = "Provision and confirm TOTP secrets"),
        (name = "authentication", description = "Exchange a code for a session token"),
        (name = "account", description = "Manage the authenticated account"),
        (name = "meta", description = "Operational endpoints"),
    ),
    modifiers(&BearerSecurity),
)]
pub struct ApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}
