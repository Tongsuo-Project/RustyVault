use openssl::x509::X509;

#[derive(Default)]
pub struct Connection {
    pub peer_addr: String,
    pub peer_tls_cert: Option<Vec<X509>>,
}
