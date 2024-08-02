use std::env;

// This is not going to happen any more since we have a default feature definition in Cargo.toml
//#[cfg(not(any(feature = "crypto_adaptor_openssl", feature = "crypto_adaptor_tongsuo")))]
//compile_error! {
//    r#"
//    No cryptography adaptor is enabled!
//
//    In RustyVault, the real cryptographic operations are done via "crypto_adaptor"s.
//
//    A crypto adaptor is a module that conveys and translates high level cryptography
//    operations like encryption, signing into the APIs provided by underlying cryptography
//    libraries such as OpenSSL, Tongsuo and so forth.
//
//    At current stage, only one crypto_adaptor can be enabled at compilation phase and later
//    be used at run-time. "crypto_adaptor"s are configured as 'feature's in the Cargo context.
//
//    Currently, the supported feature names of crypto adaptors are as follows, you can enable
//    them by adding one '--features crypto_adaptor_name' option when running "cargo build":
//        1. the OpenSSL adaptor: crypto_adaptor_openssl
//        2. the Tongsuo adaptor: crypto_adaptor_tongsuo
//    "#
//}

#[cfg(all(feature = "crypto_adaptor_openssl", feature = "crypto_adaptor_tongsuo"))]
compile_error! {
    r#"
    Only one cryptography adapator can be enabled!

    In RustyVault, the real cryptographic operations are done via "crypto_adaptor"s.

    A crypto adaptor is a module that conveys and translates high level cryptography
    operations like encryption, signing into the APIs provided by underlying cryptography
    libraries such as OpenSSL, Tongsuo and so forth.

    At current stage, only one crypto_adaptor can be enabled at compilation phase and later
    be used at run-time. "crypto_adaptor"s are configured as 'feature's in the Cargo context.

    Currently, the supported feature names of crypto adaptors are as follows, you can enable
    them by adding one '--features crypto_adaptor_name' option when running "cargo build":
        1. the OpenSSL adaptor: crypto_adaptor_openssl
        2. the Tongsuo adaptor: crypto_adaptor_tongsuo
    "#
}

fn main() {
    if let Ok(_) = env::var("DEP_OPENSSL_TONGSUO") {
        println!("cargo:rustc-cfg=tongsuo");
    } else if cfg!(feature = "crypto_adaptor_tongsuo") {
        println!("cargo:rustc-cfg=tongsuo");
    }
}
