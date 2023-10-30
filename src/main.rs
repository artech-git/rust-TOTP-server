use axum::{routing::{get, post}, Router};
use db::NormalDBClient;
use shuttle_axum::ShuttleAxum; 

extern crate rand;

mod auth;
mod db;
mod eval_constants;
mod obj;
mod operation;
mod test;
mod error; 

use crate::auth::{authentication, otp_verification, register_user, verification};

#[shuttle_runtime::main]
async fn axum() -> ShuttleAxum {

    tracing_subscriber::fmt::init();
    
    let db_client = NormalDBClient::new("./my_db"); 

    // setup the routes which will going to be passed to the respective debug assertion
    let app = Router::new()
        .route("/signin", post(register_user))
        .route("/login", post(verification))
        .route("/verify", post(otp_verification))
        .route("/authorize", post(authentication))
        .with_state(db_client);

    let app_version = Router::new()
        .nest("/v1", app); 
    
    // axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
    //     .http2_enable_connect_protocol() //enable http2 connection procedure for the axum server
    //     .serve(app.into_make_service()) //serve our application on this route
    //     .await
    //     .unwrap();

    Ok(app_version.into())
}
