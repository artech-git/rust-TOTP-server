use axum::{routing::get, Router};

#[macro_use]
extern crate lazy_static;

extern crate rand;

mod auth;
mod db;
mod obj;
mod operation;

use crate::auth::{register_user, verification};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/register", get(register_user))
        .route("/verify", get(verification));

    #[cfg(debug_assertions)]
    {
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .http2_enable_connect_protocol()
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    // If we compile in release mode, use the Lambda Runtime
    #[cfg(not(debug_assertions))]
    {
        // To run with AWS Lambda runtime, wrap in our `LambdaLayer`
        let app = tower::ServiceBuilder::new()
            .layer(axum_aws_lambda::LambdaLayer::default())
            .service(app);

        lambda_http::run(app).await.unwrap();
    }
}
