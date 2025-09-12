use aws_sdk_dynamodb::{
    model::{AttributeValue, Select},
    Client, Endpoint, Region,
};
use aws_types::Credentials;
use http::Uri;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::Result;

#[derive(Clone)]
pub struct Db {
    pub client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DbUser {
    pub email: String,
    pub secret: String,
}

impl Db {
    pub async fn new(config: &Config) -> Result<Self> {
        let creds = Credentials::from_keys(
            config.db_access_key.clone(),
            config.db_secret_access_key.clone(),
            None,
        );

        let dynamodb_local_config = aws_sdk_dynamodb::config::Builder::new()
            .credentials_provider(creds)
            .region(Region::new(config.aws_region.clone()))
            .endpoint_resolver(Endpoint::immutable(
                config.aws_region_url.clone().parse::<Uri>()?,
            ))
            .build();

        let client = Client::from_conf(dynamodb_local_config);

        Ok(Self { client })
    }

    pub async fn get_user_secret(&self, table_name: &str, email: &str) -> Result<Option<String>> {
        let key = "user_email".to_string();
        let user_av = AttributeValue::S(email.to_owned());

        let res = self
            .client
            .query()
            .table_name(table_name)
            .key_condition_expression("#key = :value".to_string())
            .expression_attribute_names("#key".to_string(), key)
            .expression_attribute_values(":value".to_string(), user_av)
            .select(Select::AllAttributes)
            .send()
            .await?;

        if let Some(items) = res.items {
            if !items.is_empty() {
                if let Some(secret_av) = items[0].get("secret") {
                    if let Ok(secret) = secret_av.as_s() {
                        return Ok(Some(secret.to_string()));
                    }
                }
            }
        }
        Ok(None)
    }

    pub async fn insert_user(&self, table_name: &str, user: &DbUser) -> Result<()> {
        let email_av = AttributeValue::S(user.email.clone());
        let secret_av = AttributeValue::S(user.secret.clone());

        self.client
            .put_item()
            .table_name(table_name)
            .item("user_email", email_av)
            .item("secret", secret_av)
            .send()
            .await?;

        Ok(())
    }
}
