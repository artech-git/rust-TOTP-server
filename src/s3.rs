use aws_sdk_dynamodb::{Client, Endpoint, Region};
use aws_types::Credentials;
use http::Uri;
use once_cell::sync::Lazy;

use crate::obj::KEY_MAP;


pub static S3_OBJ: Lazy<aws_sdk_s3control::config::Config> = Lazy::new(|| {

    let region = KEY_MAP
        .get(&"aws-region".to_string())
        .unwrap_or(&"ap-south-1".to_string())
        .to_owned();

    let url = KEY_MAP
        .get(&"aws-region-url".to_string())
        .unwrap_or(&format!("https://dynamodb.{}.amazonaws.com/", region)) //TODO change to s3 container object
        .to_owned()
        .parse::<Uri>()
        .unwrap();

    let s3_key = match KEY_MAP.get(&"s3-access-key".to_string()) {
        Some(v) => {
            tracing::log::info!("s3 access key present");
            v
        }
        None => {
            tracing::log::warn!("s3 access key is not present");
            panic!();
        }
    };

    let s3_sec = match KEY_MAP.get(&"s3-secret-access-key".to_string()) {
        Some(v) => {
            tracing::log::info!("s3 secret key present");
            v
        }
        None => {
            tracing::log::warn!("s3 secret key is not present");
            panic!();
        }
    };

    let creds = Credentials::from_keys(s3_key, s3_sec, None);

    let s3_local_config = aws_sdk_s3control::config::Builder::new()
        .credentials_provider(creds)
        .region(Region::new(region))
        .endpoint_resolver(Endpoint::immutable(url))
        .build();

    return s3_local_config;
});