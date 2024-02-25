use crate::obj::FILE_PATH;
use crate::obj::KEY_MAP;
use once_cell::sync::OnceCell;

pub fn get_key_size_value() -> usize {
    let mut key_size = OnceCell::new();
    key_size.get_or_init(|| match KEY_MAP.get("KEY_SIZE") {
        Some(value) => match value.parse::<usize>() {
            Ok(key_size) => key_size,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under KEY_SIZE param in {FILE_PATH} file: {}",
                    e
                );
                panic!("{}", e);
            }
        },
        None => {
            tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    })
}

pub fn get_step_size_value() -> u64 {
    let mut step_size = OnceCell::new();
    step_size.get_or_init(|| match KEY_MAP.get("STEP_SIZE") {
        Some(value) => match value.parse::<u64>() {
            Ok(step_size) => step_size,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under KEY_SIZE param in {FILE_PATH} file: {}",
                    e
                );
                panic!("{}", e);
            }
        },
        None => {
            tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    })
}

pub fn get_totp_size_value() -> u32 {
    let mut totp_size = OnceCell::new();
    totp_size.get_or_init(|| match KEY_MAP.get("TOTP_SIZE") {
        Some(value) => match value.parse::<u32>() {
            Ok(totp_size) => totp_size,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under TOTP_SIZE param in {FILE_PATH} file: {}",
                    e
                );
                panic!("{}", e);
            }
        },
        None => {
            tracing::log::error!("TOTP_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    })
}
