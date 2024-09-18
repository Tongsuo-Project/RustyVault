use openssl::{
    x509::X509,
};

#[repr(u32)]
pub enum FailureMode {
    OcspFailOpenNotSet = 0,
    FailOpenTrue = 1,
    FailOpenFalse = 2,
}

pub struct OcspConfig {
    pub enable: bool,
    pub extra_ca: Vec<X509>,
    pub servers_override: Vec<String>,
    pub failure_mode: FailureMode,
    pub query_all_servers: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        OcspConfig {
            enable: false,
            extra_ca: Vec::new(),
            servers_override: Vec::new(),
            failure_mode: FailureMode::OcspFailOpenNotSet,
            query_all_servers: false,
        }
    }
}
