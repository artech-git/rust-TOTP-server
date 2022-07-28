use async_once::AsyncOnce;
use aws_sdk_dynamodb::{Client, Endpoint, Region};
use http::Uri;

use crate::obj::KEY_MAP;

lazy_static! {
    pub static ref DB_AWS: AsyncOnce<Client> = AsyncOnce::new(async {
        let config = aws_config::from_env().load().await;

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

        let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::from(&config)
            .region(Region::new(region))
            .endpoint_resolver(Endpoint::immutable(url))
            .build();

        let client = Client::from_conf(dynamodb_local_config);
        return client;
    });
}
