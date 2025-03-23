use std::fmt::Debug;

pub fn dprint<T: Debug>(debug: bool, message: &str, value: T) {
    if debug {
        println!("[DEBUG] {}: {:?}", message, value);
    }
}
