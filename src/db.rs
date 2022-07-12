
use std::{collections::HashMap};
use once_cell::sync::Lazy;


pub static mut DB: Lazy<HashMap<String, String>> = Lazy::new( || {
    let mut hm: HashMap<String, String> = HashMap::new();
    return hm;
});