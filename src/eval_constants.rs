use crate::obj::FILE_PATH;
use crate::obj::KEY_MAP;

pub fn get_key_size_value() -> usize {
    lazy_static! {
        pub static ref VALUE: String = match KEY_MAP.get("KEY_SIZE") {
            Some(v) => v.to_owned(),
            None => {
                tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
                panic!();
            }
        };
        pub static ref KEY_SIZE: usize = match VALUE.parse::<usize>() {
            Ok(v) => v,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under KEY_SIZE param in {FILE_PATH} file"
                );
                panic!("{e}");
            }
        };
    }

    return *KEY_SIZE;
}

pub fn get_step_size_value() -> u64 {
    lazy_static! {
        pub static ref VALUE: String = match KEY_MAP.get("STEP_SIZE") {
            Some(v) => v.to_owned(),
            None => {
                tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
                panic!();
            }
        };
        pub static ref STEP_SIZE: u64 = match VALUE.parse::<u64>() {
            Ok(v) => v,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under KEY_SIZE param in {FILE_PATH} file"
                );
                panic!("{e}");
            }
        };
    }

    return *STEP_SIZE;
}

pub fn get_totp_size_value() -> u32 {
    lazy_static! {
        pub static ref VALUE: String = match KEY_MAP.get("TOTP_SIZE") {
            Some(v) => v.to_owned(),
            None => {
                tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
                panic!();
            }
        };
        pub static ref STEP_SIZE: u32 = match VALUE.parse::<u32>() {
            Ok(v) => v,
            Err(e) => {
                tracing::log::error!(
                    "Invalid value found under KEY_SIZE param in {FILE_PATH} file"
                );
                panic!("{e}");
            }
        };
    }

    return *STEP_SIZE;
}
