use axum::{routing::get, Extension, Router};

extern crate rand;

mod db;
mod eval_constants;
mod handles;
mod obj;
mod operation;
mod test;

use crate::handles::{authentication, otp_verification, register_user, verification};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let conn_str = "postgres://postgres.qyrhhghewyfcwffblxxr:FTPkGGQaQB2AuxOr@aws-0-eu-central-1.pooler.supabase.com:5432/postgres";
    let pooled_conn = sqlx::pool::Pool::connect(conn_str).await.unwrap();

    // setup the routes which will going to be passed to the respective debug assertion
    let app = Router::new()
        .route("/signin", get(register_user))
        .route("/login", get(verification))
        .route("/verify", get(otp_verification))
        .route("/authorize", get(authentication))
        .extension(Extension(pooled_conn));

    #[cfg(debug_assertions)] // select the following block if the --release flag is not present
    {
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .http2_enable_connect_protocol() //enable http2 connection procedure for the axum server
            .serve(app.into_make_service()) //serve our application on this route
            .await
            .unwrap();
    }

    #[cfg(not(debug_assertions))] // select the following code block on --release builds
    {
        // To run with AWS Lambda runtime, wrap in our `LambdaLayer`
        let app = tower::ServiceBuilder::new()
            .layer(axum_aws_lambda::LambdaLayer::default())
            .service(app);

        lambda_http::run(app).await.unwrap();
    }
}
