use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub aws_region: String,
    pub aws_region_url: String,
    pub db_access_key: String,
    pub db_secret_access_key: String,
    pub auth_table: String,
    #[serde(rename = "KEY_SIZE")]
    pub key_size: usize,
    #[serde(rename = "STEP_SIZE")]
    pub step_size: u64,
    #[serde(rename = "TOTP_SIZE")]
    pub totp_size: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name("./settings.toml"))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        cfg.try_deserialize()
    }
}
