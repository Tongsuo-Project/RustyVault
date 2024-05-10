use std::env;

fn main() {
    if let Ok(_) = env::var("DEP_OPENSSL_TONGSUO") {
        println!("cargo:rustc-cfg=tongsuo");
    }
}
