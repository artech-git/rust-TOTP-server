use async_once::AsyncOnce;
use aws_sdk_dynamodb::{Client, Endpoint, Region};
use http::Uri;

lazy_static! {
    pub static ref DB_AWS: AsyncOnce<Client> = AsyncOnce::new(async {
        let config = aws_config::from_env().load().await;

        let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::from(&config)
            .region(Region::new("ap-south-1"))
            .endpoint_resolver(Endpoint::immutable(Uri::from_static(
                "https://dynamodb.ap-south-1.amazonaws.com/totp-auth",
            )))
            .build();

        let client = Client::from_conf(dynamodb_local_config);
        return client;
    });
}
