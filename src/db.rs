use once_cell::sync::Lazy;
use std::collections::HashMap;

pub static mut DB: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let hm: HashMap<String, String> = HashMap::new();
    return hm;
});
