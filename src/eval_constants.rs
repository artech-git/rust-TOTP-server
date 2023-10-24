use crate::obj::FILE_PATH;
use crate::obj::KEY_MAP;

use once_cell::unsync::Lazy; 

#[allow(non_snake_case)]
pub fn get_key_size_value() -> usize {
    
    let VALUE = Lazy::new( || match KEY_MAP.get("KEY_SIZE") {
        Some(v) => v.to_owned(),
        None => {
            tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    });
    
    let KEY_SIZE = Lazy::new( || match VALUE.parse::<usize>() {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!("Invalid value found under KEY_SIZE param in {FILE_PATH} file");
            panic!("{e}");
        }
    });

    return *KEY_SIZE;
}

#[allow(non_snake_case)]
pub fn get_step_size_value() -> u64 {
    
    let VALUE = Lazy::new( || match KEY_MAP.get("STEP_SIZE") {
        Some(v) => v.to_owned(),
        None => {
            tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    });

    let STEP_SIZE = Lazy::new( || match VALUE.parse::<u64>() {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!(
                "Invalid value found under KEY_SIZE param in {FILE_PATH} file"
            );
            panic!("{e}");
        }
    });

    return *STEP_SIZE;
}

#[allow(non_snake_case)]
pub fn get_totp_size_value() -> u32 {
    
    let VALUE = Lazy::new( || match KEY_MAP.get("TOTP_SIZE") {
        Some(v) => v.to_owned(),
        None => {
            tracing::log::error!("KEY_SIZE value not present in the : {}", FILE_PATH);
            panic!();
        }
    });

    let STEP_SIZE = Lazy::new( || match VALUE.parse::<u32>() {
        Ok(v) => v,
        Err(e) => {
            tracing::log::error!(
                "Invalid value found under KEY_SIZE param in {FILE_PATH} file"
            );
            panic!("{e}");
        }
    });

    return *STEP_SIZE;
}
