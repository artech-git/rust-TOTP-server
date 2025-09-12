use axum::{routing::get, Router};
use std::sync::Arc;

mod auth;
mod config;
mod db;
mod error;
mod obj;
mod operation;
mod test;

use crate::{
    auth::{register_user, verification},
    config::Config,
    db::Db,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::from_env().expect("failed to load config");
    let db = Db::new(&config).await.expect("failed to connect to db");

    let shared_state = Arc::new(db);
    let config_state = Arc::new(config);

    // setup the routes which will going to be passed to the respective debug assertion
    let app = Router::new()
        .route("/signin", get(register_user))
        .route("/login", get(verification))
        .layer(axum::extract::Extension(shared_state))
        .layer(axum::extract::Extension(config_state));

    #[cfg(debug_assertions)] // select the following block if the --release flag is not present
    {
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(app.into_make_service()) //serve our application on this route
            .await
            .unwrap();
    }

    // If we compile in release mode, use the Lambda Runtime
    #[cfg(not(debug_assertions))] // select the following code block on --release builds
    {
        // To run with AWS Lambda runtime, wrap in our `LambdaLayer`
        let app = tower::ServiceBuilder::new()
            .layer(axum_aws_lambda::LambdaLayer::default())
            .service(app);

        lambda_http::run(app).await.unwrap();
    }
}
