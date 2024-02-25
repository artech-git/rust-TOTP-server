use sqlx::{query, Pool, Postgres, Row};

use sqlx::Executor;
use sqlx::Statement;

pub async fn discover_user(db_handle: &Pool<Postgres>, email: &String) -> Option<()> {
    let mut query = format!("select {} from User ", email).as_str();
    let mut res = db_handle.execute(query).await;
    res.ok().map(|_| ())
}

pub async fn insert_user(
    mut db_handle: &Pool<Postgres>,
    email: &String,
    secret: &String,
) -> Option<()> {
    let query = sqlx::query!(
        "INSERT INTO VerfiyUser (email, token) VALUES ($1, $2)",
        email,
        secret
    );

    let mut resp = query.fetch_one(db_handle).map(|e| ()).ok();
    // let mut resp = db_handle.execute(query).await.map(|e| ()).ok();
    resp
}

pub async fn get_user_key(db_handle: &Pool<Postgres>, email: &String) -> Option<String> {
    // Table_name: VerifyUser
    // fields uuid, email, token

    // insert the data into the VerifyUser field of database.
    // let query = format!("SELECT token from VerifyUser WHERE email='{}'", email).as_str();

    let query = sqlx::query!("SELECT token from VerifyUser WHERE email=$1 ", email);

    let res = db_handle.fetch_one(query).await.ok();
    if let Some(res) = res {
        if res.is_empty() {
            return None;
        }
        Some(res.get(0))
    } else {
        return None;
    }
}
