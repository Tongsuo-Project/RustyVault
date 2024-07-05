use openssl::x509::X509;

pub struct Connection {
    pub peer_addr: String,
    pub peer_tls_cert: Option<Vec<X509>>,
}

impl Default for Connection {
    fn default() -> Self {
        Self { peer_addr: String::new(), peer_tls_cert: None }
    }
}
