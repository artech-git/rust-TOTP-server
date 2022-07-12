use axum::{
    routing::get,
    Router,
};

#[macro_use]
extern crate lazy_static;

mod auth;
mod operation;
mod db;

use crate::auth::{register_user,  verification};

#[tokio::main]
async fn main() {
    // build our application with a single route

    let app = Router::new().route("/register", get( register_user))
                            .route("/verify", get(verification));

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}