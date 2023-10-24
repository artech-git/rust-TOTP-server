use axum::{routing::post, Router};

extern crate rand;

mod auth;
mod db;
mod eval_constants;
mod obj;
mod operation;
mod test;

use crate::auth::{authentication, otp_verification, register_user, verification};

#[tokio::main]
async fn main() {
    
    tracing_subscriber::fmt::init();

    // setup the routes which will going to be passed to the respective debug assertion
    let app = Router::new()
        .route("/signin", post(register_user))
        .route("/login", post(verification))
        .route("/verify", post(otp_verification))
        .route("/authorize", post(authentication));

    #[cfg(debug_assertions)] // select the following block if the --release flag is not present
    {
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .http2_enable_connect_protocol() //enable http2 connection procedure for the axum server
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
