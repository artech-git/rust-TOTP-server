use aws_sdk_dynamodb::{Client, Endpoint, Region};
use aws_types::Credentials;
use http::Uri;
use once_cell::sync::Lazy;

use crate::obj::KEY_MAP;

pub static DynamoDBClient: Lazy<Client> = Lazy::new(|| {
    let region = KEY_MAP
        .get(&"aws-region".to_string())
        .unwrap_or(&"ap-south-1".to_string())
        .to_owned();

    let url = KEY_MAP
        .get(&"aws-region-url".to_string())
        .unwrap_or(&format!("https://dynamodb.{}.amazonaws.com/", region))
        .to_owned()
        .parse::<Uri>()
        .unwrap();

    let db_key = match KEY_MAP.get(&"db-access-key".to_string()) {
        Some(v) => {
            tracing::log::info!("access key present");
            v
        }
        None => {
            tracing::log::warn!("access key is not present");
            panic!();
        }
    };

    let db_sec = match KEY_MAP.get(&"db-secret-access-key".to_string()) {
        Some(v) => {
            tracing::log::info!("secret key present");
            v
        }
        None => {
            tracing::log::warn!("secret key is not present");
            panic!();
        }
    };

    let creds = Credentials::from_keys(db_key, db_sec, None);

    let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::new()
        .credentials_provider(creds)
        .region(Region::new(region))
        .endpoint_resolver(Endpoint::immutable(url))
        .build();

    let client = Client::from_conf(dynamodb_local_config);

    return client;
});
