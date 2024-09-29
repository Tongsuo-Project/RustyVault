use libc::c_int;
use std::{
    collections::HashMap,
    default::Default,
    env, fs,
    io::prelude::*,
    path::Path,
    sync::{Arc, Barrier, RwLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix_web::{
    dev::Server,
    middleware::{self, from_fn},
    web, App, HttpResponse, HttpServer,
};
use anyhow::format_err;
use foreign_types::ForeignType;
use humantime::parse_duration;
use lazy_static::lazy_static;
use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        },
        X509Extension, X509NameBuilder, X509Ref, X509,
    },
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore,
};
use serde_json::{json, Map, Value};
use tokio::sync::oneshot;
use ureq::AgentBuilder;

use crate::{
    core::{Core, SealConfig},
    errors::RvError,
    http,
    logical::{Operation, Request, Response},
    metrics::{manager::MetricsManager, middleware::metrics_midleware, system_metrics::SystemMetrics},
    rv_error_response,
    storage::{self, Backend},
    utils::cert::Certificate,
};

lazy_static! {
    pub static ref TEST_DIR: &'static str = "rusty_vault_test";
}

#[derive(Debug, Clone)]
pub struct TestTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct TestTlsClientAuth {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub struct TestHttpServer {
    pub name: String,
    pub mount_path: String,
    pub core: Arc<RwLock<Core>>,
    pub root_token: String,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub tls_enable: bool,
    pub listen_addr: String,
    pub url_prefix: String,
    pub stop_tx: Option<oneshot::Sender<()>>,
    pub thread: Option<thread::JoinHandle<()>>,
}

impl TestHttpServer {
    pub fn new(name: &str, tls_enable: bool) -> Self {
        let barrier = Arc::new(Barrier::new(2));
        let (stop_tx, stop_rx) = oneshot::channel();
        let (root_token, core) = test_rusty_vault_init(name);

        let mut scheme = "http";
        let mut ca_cert_pem = "".into();
        let mut ca_key_pem = "".into();
        let mut server_cert_pem = "".into();
        let mut server_key_pem = "".into();
        let mut test_tls_config = None;

        if tls_enable {
            (ca_cert_pem, ca_key_pem) =
                new_test_cert(true, true, true, "test-ca", None, None, None, None, None, None).unwrap();
            (server_cert_pem, server_key_pem) = new_test_cert(
                false,
                true,
                true,
                "localhost",
                Some("localhost"),
                Some("127.0.0.1"),
                None,
                None,
                Some(ca_cert_pem.clone()),
                Some(ca_key_pem.clone()),
            )
            .unwrap();

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let test_certs_dir = env::temp_dir().join(format!("{}/certs/{}-{}", *TEST_DIR, name, now).as_str());
            let dir = test_certs_dir.to_string_lossy().into_owned();
            assert!(fs::create_dir_all(&test_certs_dir).is_ok());

            let ca_path = format!("{}/ca.crt", dir);
            let cert_path = format!("{}/server.crt", dir);
            let key_path = format!("{}/key.pem", dir);

            let mut ca_file = fs::File::create(&ca_path).unwrap();
            assert!(ca_file.write_all(ca_cert_pem.as_bytes()).is_ok());

            let mut cert_file = fs::File::create(&cert_path).unwrap();
            assert!(cert_file.write_all(server_cert_pem.as_bytes()).is_ok());

            let mut key_file = fs::File::create(&key_path).unwrap();
            assert!(key_file.write_all(server_key_pem.as_bytes()).is_ok());

            test_tls_config = Some(TestTlsConfig { cert_path, key_path });

            scheme = "https";
        }

        let (server, listen_addr) = new_test_http_server(core.clone(), test_tls_config).unwrap();
        let server_thread = start_test_http_server(server, Arc::clone(&barrier), stop_rx);

        barrier.wait();

        let url_prefix = format!("{}://{}/v1", scheme, listen_addr);

        Self {
            name: name.to_string(),
            core,
            root_token,
            tls_enable,
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            listen_addr,
            url_prefix,
            mount_path: "".into(),
            stop_tx: Some(stop_tx),
            thread: Some(server_thread),
        }
    }

    pub fn new_with_prometheus(name: &str, tls_enable: bool) -> Self {
        let barrier = Arc::new(Barrier::new(2));
        let (stop_tx, stop_rx) = oneshot::channel();
        let (root_token, core) = test_rusty_vault_init(name);

        let mut scheme = "http";
        let mut ca_cert_pem = "".into();
        let mut ca_key_pem = "".into();
        let mut server_cert_pem = "".into();
        let mut server_key_pem = "".into();
        let mut test_tls_config = None;

        if tls_enable {
            (ca_cert_pem, ca_key_pem) =
                new_test_cert(true, true, true, "test-ca", None, None, None, None, None, None).unwrap();
            (server_cert_pem, server_key_pem) = new_test_cert(
                false,
                true,
                true,
                "localhost",
                Some("localhost"),
                Some("127.0.0.1"),
                None,
                None,
                Some(ca_cert_pem.clone()),
                Some(ca_key_pem.clone()),
            )
            .unwrap();

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let test_certs_dir = env::temp_dir().join(format!("{}/certs/{}-{}", *TEST_DIR, name, now).as_str());
            let dir = test_certs_dir.to_string_lossy().into_owned();
            assert!(fs::create_dir_all(&test_certs_dir).is_ok());

            let ca_path = format!("{}/ca.crt", dir);
            let cert_path = format!("{}/server.crt", dir);
            let key_path = format!("{}/key.pem", dir);

            let mut ca_file = fs::File::create(&ca_path).unwrap();
            assert!(ca_file.write_all(ca_cert_pem.as_bytes()).is_ok());

            let mut cert_file = fs::File::create(&cert_path).unwrap();
            assert!(cert_file.write_all(server_cert_pem.as_bytes()).is_ok());

            let mut key_file = fs::File::create(&key_path).unwrap();
            assert!(key_file.write_all(server_key_pem.as_bytes()).is_ok());

            test_tls_config = Some(TestTlsConfig { cert_path, key_path });

            scheme = "https";
        }

        let collection_interval: u64 = 15;
        let metrics_manager = Arc::new(RwLock::new(MetricsManager::new(collection_interval)));
        let system_metrics = Arc::clone(&metrics_manager.read().unwrap().system_metrics);

        let (server, listen_addr) =
            new_test_http_server_with_prometheus(core.clone(), metrics_manager, test_tls_config).unwrap();
        let server_thread =
            start_test_http_server_with_prometheus(server, Arc::clone(&barrier), stop_rx, system_metrics);

        barrier.wait();

        let url_prefix = format!("{}://{}", scheme, listen_addr);

        Self {
            name: name.to_string(),
            core,
            root_token,
            tls_enable,
            ca_cert_pem,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
            listen_addr,
            url_prefix,
            mount_path: "".into(),
            stop_tx: Some(stop_tx),
            thread: Some(server_thread),
        }
    }

    pub fn mount(&mut self, path: &str, mtype: &str) -> Result<(u16, Value), RvError> {
        let data = json!({
            "type": mtype,
        })
        .as_object()
        .unwrap()
        .clone();
        let (status, resp) = self.write(&format!("sys/mounts/{}", path), Some(data), None)?;
        if status == 200 || status == 204 {
            self.mount_path = path.into();
        }

        Ok((status, resp))
    }

    pub fn mount_auth(&mut self, path: &str, atype: &str) -> Result<(u16, Value), RvError> {
        let data = json!({
            "type": atype,
        })
        .as_object()
        .unwrap()
        .clone();
        let (status, resp) = self.write(&format!("sys/auth/{}", path), Some(data), None)?;
        if status == 200 || status == 204 {
            self.mount_path = path.into();
        }

        Ok((status, resp))
    }

    pub fn login(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        self.request("POST", path, data, None, tls_client_auth)
    }

    pub fn list(&self, path: &str, token: Option<&str>) -> Result<(u16, Value), RvError> {
        self.request("LIST", path, None, token, None)
    }

    pub fn read(&self, path: &str, token: Option<&str>) -> Result<(u16, Value), RvError> {
        self.request("GET", path, None, token, None)
    }

    pub fn write(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
    ) -> Result<(u16, Value), RvError> {
        self.request("POST", path, data, token, None)
    }

    pub fn delete(
        &self,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
    ) -> Result<(u16, Value), RvError> {
        self.request("DELETE", path, data, token, None)
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        let url = format!("{}/{}", self.url_prefix, path);
        println!("request url: {}, method: {}", url, method);
        let tk = token.unwrap_or(&self.root_token);
        let mut req = if self.tls_enable {
            // Create rustls ClientConfig
            let tls_config;
            if let Some(client_auth) = tls_client_auth {
                let ca_pem = pem::parse(client_auth.ca_pem.as_bytes())?;
                let ca_cert = CertificateDer::from_slice(ca_pem.contents());

                let mut ca_store = RootCertStore::empty();
                ca_store.add(ca_cert)?;

                let mut client_certs = vec![];
                let mut cert_pem = client_auth.cert_pem.as_bytes();
                loop {
                    match rustls_pemfile::read_one_from_slice(cert_pem)? {
                        Some((rustls_pemfile::Item::X509Certificate(cert), rest)) => {
                            cert_pem = rest;
                            client_certs.push(cert.into());
                        }
                        None => break,
                        _ => return Err(rv_error_response!("client cert format invalid")),
                    }
                }

                let client_key: PrivateKeyDer =
                    match rustls_pemfile::read_one_from_slice(client_auth.key_pem.as_bytes())? {
                        Some((rustls_pemfile::Item::Pkcs1Key(key), _)) => PrivateKeyDer::Pkcs1(key),
                        Some((rustls_pemfile::Item::Pkcs8Key(key), _)) => PrivateKeyDer::Pkcs8(key),
                        _ => return Err(rv_error_response!("client key format invalid")),
                    };

                tls_config = ClientConfig::builder()
                    .with_root_certificates(ca_store)
                    .with_client_auth_cert(client_certs, client_key)?;
            } else {
                let cert_pem = pem::parse(self.ca_cert_pem.as_bytes())?;
                let root_cert = CertificateDer::from_slice(cert_pem.contents());

                // Configure the root certificate
                let mut root_store = RootCertStore::empty();
                root_store.add(root_cert)?;

                tls_config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
            }

            let agent = AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .tls_config(Arc::new(tls_config))
                .build();
            agent.request(&method.to_uppercase(), &url)
        } else {
            ureq::request(&method.to_uppercase(), &url)
        };

        req = req.set("Accept", "application/json");
        if !path.ends_with("/login") {
            req = req.set("X-RustyVault-Token", tk);
        }

        let response_result = if let Some(send_data) = data { req.send_json(send_data) } else { req.call() };

        match response_result {
            Ok(response) => {
                let status = response.status();
                if status == 204 {
                    return Ok((status, json!("")));
                }
                let json: Value = response.into_json()?;
                return Ok((status, json));
            }
            Err(ureq::Error::Status(code, response)) => {
                let json: Value = response.into_json()?;
                return Ok((code, json));
            }
            Err(e) => {
                println!("Request failed: {}", e);
                return Err(RvError::UreqError { source: e });
            }
        }
    }

    pub fn request_prometheus(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>,
        token: Option<&str>,
        tls_client_auth: Option<TestTlsClientAuth>,
    ) -> Result<(u16, Value), RvError> {
        let url = format!("{}/{}", self.url_prefix, path);
        println!("request url: {}, method: {}", url, method);
        let tk = token.unwrap_or(&self.root_token);
        let mut req = if self.tls_enable {
            // Create rustls ClientConfig
            let tls_config;
            if let Some(client_auth) = tls_client_auth {
                let ca_pem = pem::parse(client_auth.ca_pem.as_bytes())?;
                let ca_cert = CertificateDer::from_slice(ca_pem.contents());

                let mut ca_store = RootCertStore::empty();
                ca_store.add(ca_cert)?;

                let mut client_certs = vec![];
                let mut cert_pem = client_auth.cert_pem.as_bytes();
                loop {
                    match rustls_pemfile::read_one_from_slice(cert_pem)? {
                        Some((rustls_pemfile::Item::X509Certificate(cert), rest)) => {
                            cert_pem = rest;
                            client_certs.push(cert.into());
                        }
                        None => break,
                        _ => return Err(rv_error_response!("client cert format invalid")),
                    }
                }

                let client_key: PrivateKeyDer =
                    match rustls_pemfile::read_one_from_slice(client_auth.key_pem.as_bytes())? {
                        Some((rustls_pemfile::Item::Pkcs1Key(key), _)) => PrivateKeyDer::Pkcs1(key),
                        Some((rustls_pemfile::Item::Pkcs8Key(key), _)) => PrivateKeyDer::Pkcs8(key),
                        _ => return Err(rv_error_response!("client key format invalid")),
                    };

                tls_config = ClientConfig::builder()
                    .with_root_certificates(ca_store)
                    .with_client_auth_cert(client_certs, client_key)?;
            } else {
                let cert_pem = pem::parse(self.ca_cert_pem.as_bytes())?;
                let root_cert = CertificateDer::from_slice(cert_pem.contents());

                // Configure the root certificate
                let mut root_store = RootCertStore::empty();
                root_store.add(root_cert)?;

                tls_config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
            }

            let agent = AgentBuilder::new()
                .timeout_connect(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .tls_config(Arc::new(tls_config))
                .build();
            agent.request(&method.to_uppercase(), &url)
        } else {
            ureq::request(&method.to_uppercase(), &url)
        };

        req = req.set("Accept", "application/json");
        if !path.ends_with("/login") {
            req = req.set("X-RustyVault-Token", tk);
        }

        let response_result = if let Some(send_data) = data { req.send_json(send_data) } else { req.call() };

        match response_result {
            Ok(response) => {
                let status = response.status();
                if status == 204 {
                    return Ok((status, json!("")));
                }
                let text = response.into_string()?;
                let wrapped_json = json!({"metrics":text});
                return Ok((status, wrapped_json));
            }
            Err(ureq::Error::Status(code, response)) => {
                let json: Value = response.into_json()?;
                return Ok((code, json));
            }
            Err(e) => {
                println!("Request failed: {}", e);
                return Err(RvError::UreqError { source: e });
            }
        }
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            tx.send(()).expect("Failed to send stop signal.");
        }

        if let Some(thread) = self.thread.take() {
            thread.join().expect("Failed to join thread.");
        }
    }
}

mod tests {
    use super::*;

    #[ctor::ctor]
    fn init() {
        let dir = env::temp_dir().join(*TEST_DIR);
        let _ = fs::remove_dir_all(&dir);
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(fs::create_dir(&dir).is_ok());
    }

    #[ctor::dtor]
    fn cleanup() {
        let dir = env::temp_dir().join(*TEST_DIR);
        let _ = fs::remove_dir_all(&dir);
    }
}

pub fn new_test_cert(
    is_ca: bool,
    client_auth: bool,
    server_auth: bool,
    common_name: &str,
    dns_sans: Option<&str>,
    ip_sans: Option<&str>,
    uri_sans: Option<&str>,
    ttl: Option<&str>,
    ca_cert_pem: Option<String>,
    ca_key_pem: Option<String>,
) -> Result<(String, String), RvError> {
    let not_before = SystemTime::now();
    let not_after = not_before + parse_duration(ttl.unwrap_or("5d"))?;
    let mut subject_name = X509NameBuilder::new()?;
    subject_name.append_entry_by_text("C", "CN")?;
    subject_name.append_entry_by_text("ST", "ZJ")?;
    subject_name.append_entry_by_text("L", "HZ")?;
    subject_name.append_entry_by_text("O", "Ant-Group")?;
    subject_name.append_entry_by_text("CN", common_name)?;

    let subject = subject_name.build();

    let mut cert = Certificate { not_before, not_after, subject, is_ca, ..Default::default() };

    if let Some(dns) = dns_sans {
        cert.dns_sans = dns.split(',').map(|s| s.trim().to_string()).collect();
    }

    if let Some(ip) = ip_sans {
        cert.ip_sans = ip.split(',').map(|s| s.trim().to_string()).collect();
    }

    if let Some(uri) = uri_sans {
        cert.uri_sans = uri.split(',').map(|s| s.trim().to_string()).collect();
    }

    let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;

    let x509 = match (ca_cert_pem, ca_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let ca_cert = X509::from_pem(cert_pem.as_bytes())?;
            let ca_key = PKey::private_key_from_pem(key_pem.as_bytes())?;
            cert_to_x509(&cert, client_auth, server_auth, Some(&ca_cert), Some(&ca_key), &pkey)?
        }
        _ => cert_to_x509(&cert, client_auth, server_auth, None, None, &pkey)?,
    };

    Ok((String::from_utf8(x509.to_pem()?)?, String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?))
}

pub fn new_test_cert_ext(
    is_ca: bool,
    client_auth: bool,
    server_auth: bool,
    common_name: &str,
    dns_sans: Option<&str>,
    ip_sans: Option<&str>,
    uri_sans: Option<&str>,
    ttl: Option<&str>,
    ca_cert_pem: Option<String>,
    ca_key_pem: Option<String>,
) -> Result<(String, String), RvError> {
    let not_before = SystemTime::now();
    let not_after = not_before + parse_duration(ttl.unwrap_or("5d"))?;
    let mut subject_name = X509NameBuilder::new()?;
    subject_name.append_entry_by_text("C", "CN")?;
    subject_name.append_entry_by_text("ST", "ZJ")?;
    subject_name.append_entry_by_text("L", "HZ")?;
    subject_name.append_entry_by_text("O", "Ant-Group")?;
    subject_name.append_entry_by_text("OU", "engineering")?;
    subject_name.append_entry_by_text("CN", common_name)?;

    let subject = subject_name.build();

    let extensions = vec![
        X509Extension::new_from_der(
            &Asn1Object::from_str("2.1.1.1").unwrap(),
            false,
            &Asn1OctetString::new_from_bytes(b"A UTF8String Extension").unwrap(),
        )
        .unwrap(),
        X509Extension::new_from_der(
            &Asn1Object::from_str("2.1.1.2").unwrap(),
            false,
            &Asn1OctetString::new_from_bytes(b"A UTF8 Extension").unwrap(),
        )
        .unwrap(),
        X509Extension::new_from_der(
            &Asn1Object::from_str("2.1.1.3").unwrap(),
            false,
            &Asn1OctetString::new_from_bytes(b"An IA5 Extension").unwrap(),
        )
        .unwrap(),
        X509Extension::new_from_der(
            &Asn1Object::from_str("2.1.1.4").unwrap(),
            false,
            &Asn1OctetString::new_from_bytes(b"A Visible Extension").unwrap(),
        )
        .unwrap(),
    ];

    let mut cert = Certificate { not_before, not_after, subject, is_ca, extensions, ..Default::default() };

    if !is_ca {
        cert.email_sans = vec!["valid@example.com".into()];
    }

    if let Some(dns) = dns_sans {
        cert.dns_sans = dns.split(',').map(|s| s.trim().to_string()).collect();
    }

    if let Some(ip) = ip_sans {
        cert.ip_sans = ip.split(',').map(|s| s.trim().to_string()).collect();
    }

    if let Some(uri) = uri_sans {
        cert.uri_sans = uri.split(',').map(|s| s.trim().to_string()).collect();
    }

    let pkey = PKey::from_rsa(Rsa::generate(2048)?)?;

    let x509 = match (ca_cert_pem, ca_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let ca_cert = X509::from_pem(cert_pem.as_bytes())?;
            let ca_key = PKey::private_key_from_pem(key_pem.as_bytes())?;
            cert_to_x509(&cert, client_auth, server_auth, Some(&ca_cert), Some(&ca_key), &pkey)?
        }
        _ => cert_to_x509(&cert, client_auth, server_auth, None, None, &pkey)?,
    };

    Ok((String::from_utf8(x509.to_pem()?)?, String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?))
}

pub fn cert_to_x509(
    cert: &Certificate,
    client_auth: bool,
    server_auth: bool,
    ca_cert: Option<&X509Ref>,
    ca_key: Option<&PKey<Private>>,
    private_key: &PKey<Private>,
) -> Result<X509, RvError> {
    let mut builder = X509::builder()?;
    builder.set_version(cert.version)?;
    let serial_number = cert.serial_number.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;
    builder.set_subject_name(&cert.subject)?;
    if ca_cert.is_some() {
        builder.set_issuer_name(ca_cert.unwrap().subject_name())?;
    } else {
        builder.set_issuer_name(&cert.subject)?;
    }
    builder.set_pubkey(private_key)?;

    let not_before_dur = cert.not_before.duration_since(UNIX_EPOCH)?;
    let not_before = Asn1Time::from_unix(not_before_dur.as_secs() as i64)?;
    builder.set_not_before(&not_before)?;

    let not_after_dur = cert.not_after.duration_since(UNIX_EPOCH)?;
    let not_after_sec = not_after_dur.as_secs();
    let not_after = Asn1Time::from_unix(not_after_sec as i64)?;
    builder.set_not_after(&not_after)?;

    let mut san_ext = SubjectAlternativeName::new();
    for dns in &cert.dns_sans {
        san_ext.dns(dns.as_str());
    }

    for email in &cert.email_sans {
        san_ext.email(email.as_str());
    }

    for ip in &cert.ip_sans {
        san_ext.ip(ip.as_str());
    }

    for uri in &cert.uri_sans {
        san_ext.uri(uri.as_str());
    }

    if (cert.dns_sans.len() | cert.email_sans.len() | cert.ip_sans.len() | cert.uri_sans.len()) > 0 {
        builder.append_extension(san_ext.build(&builder.x509v3_context(ca_cert, None))?)?;
    }

    for ext in &cert.extensions {
        builder.append_extension2(ext)?;
    }

    if cert.is_ca {
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build()?)?;
    } else {
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(
            KeyUsage::new().critical().non_repudiation().digital_signature().key_encipherment().build()?,
        )?;
        let mut ext = &mut ExtendedKeyUsage::new();
        if client_auth {
            ext = ext.client_auth();
        }

        if server_auth {
            ext = ext.server_auth();
        }
        //builder.append_extension(ExtendedKeyUsage::new().server_auth().client_auth().build()?)?;
        builder.append_extension(ext.build()?)?;
    }

    let subject_key_id = SubjectKeyIdentifier::new().build(&builder.x509v3_context(ca_cert, None))?;
    builder.append_extension(subject_key_id)?;

    let authority_key_id =
        AuthorityKeyIdentifier::new().keyid(true).issuer(false).build(&builder.x509v3_context(ca_cert, None))?;
    builder.append_extension(authority_key_id)?;

    if ca_key.is_some() {
        builder.sign(ca_key.as_ref().unwrap(), MessageDigest::sha256())?;
    } else {
        builder.sign(private_key, MessageDigest::sha256())?;
    }

    Ok(builder.build())
}

pub unsafe fn new_test_crl(revoked_cert_pem: &str, ca_cert_pem: &str, ca_key_pem: &str) -> Result<String, RvError> {
    let revoked_cert = X509::from_pem(revoked_cert_pem.as_bytes())?;
    let ca_cert = X509::from_pem(ca_cert_pem.as_bytes())?;
    let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes())?;

    let crl = openssl_sys::X509_CRL_new();
    if crl.is_null() {
        return Err(rv_error_response!("X509_CRL_new failed."));
    }

    if openssl_sys::X509_CRL_set_version(crl, 0) == 0 {
        openssl_sys::X509_CRL_free(crl);
        return Err(rv_error_response!("X509_CRL_set_version failed."));
    }

    let issuer_name = openssl_sys::X509_get_subject_name(ca_cert.as_ptr());
    if openssl_sys::X509_CRL_set_issuer_name(crl, issuer_name) == 0 {
        openssl_sys::X509_CRL_free(crl);
        return Err(rv_error_response!("X509_CRL_set_issuer_name failed."));
    }

    let last_update = Asn1Time::days_from_now(0)?;
    let next_update = Asn1Time::days_from_now(7)?;

    openssl_sys::X509_CRL_set1_lastUpdate(crl, last_update.as_ptr());
    openssl_sys::X509_CRL_set1_nextUpdate(crl, next_update.as_ptr());

    let revoked = openssl_sys::X509_REVOKED_new();
    if revoked.is_null() {
        openssl_sys::X509_CRL_free(crl);
        return Err(rv_error_response!("X509_REVOKED_new failed."));
    }

    let serial_number = openssl_sys::X509_get_serialNumber(revoked_cert.as_ptr());
    openssl_sys::X509_REVOKED_set_serialNumber(revoked, serial_number);
    openssl_sys::X509_REVOKED_set_revocationDate(revoked, last_update.as_ptr());
    openssl_sys::X509_CRL_add0_revoked(crl, revoked);

    if openssl_sys::X509_CRL_sign(crl, ca_key.as_ptr(), openssl_sys::EVP_sha256()) == 0 {
        openssl_sys::X509_REVOKED_free(revoked);
        openssl_sys::X509_CRL_free(crl);
        return Err(rv_error_response!("X509_CRL_sign failed."));
    }

    let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
    openssl_sys::PEM_write_bio_X509_CRL(bio, crl);

    let mut buffer = vec![0u8; 2048];
    let _ = openssl_sys::BIO_read(bio, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len() as c_int);

    openssl_sys::BIO_free_all(bio);
    openssl_sys::X509_CRL_free(crl);

    return Ok(String::from_utf8_lossy(&buffer).into());
}

pub fn test_backend(name: &str) -> Arc<dyn Backend> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let test_dir = env::temp_dir().join(format!("{}/{}-{}", *TEST_DIR, name, now).as_str());
    let dir = test_dir.to_string_lossy().into_owned();
    assert!(fs::create_dir(&test_dir).is_ok());

    println!("test backend init, dir: {}", dir);

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".to_string(), Value::String(dir));

    let backend = storage::new_backend("file", &conf);
    assert!(backend.is_ok());

    backend.unwrap()
}

pub fn test_rusty_vault_init(name: &str) -> (String, Arc<RwLock<Core>>) {
    let root_token;
    let backend = test_backend(name);
    let barrier = storage::barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
    let c = Arc::new(RwLock::new(Core { physical: backend, barrier: Arc::new(barrier), ..Default::default() }));

    {
        let mut core = c.write().unwrap();
        assert!(core.config(Arc::clone(&c), None).is_ok());

        let seal_config = SealConfig { secret_shares: 10, secret_threshold: 5 };

        let result = core.init(&seal_config);
        assert!(result.is_ok());
        let init_result = result.unwrap();
        println!("init_result: {:?}", init_result);

        let mut unsealed = false;
        for i in 0..seal_config.secret_threshold {
            let key = &init_result.secret_shares[i as usize];
            let unseal = core.unseal(key);
            assert!(unseal.is_ok());
            unsealed = unseal.unwrap();
        }

        root_token = init_result.root_token;
        println!("root_token: {:?}", root_token);

        assert!(unsealed);
    }

    (root_token, c)
}

pub fn new_test_http_server(
    core: Arc<RwLock<Core>>,
    tls_config: Option<TestTlsConfig>,
) -> Result<(Server, String), RvError> {
    let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(core.clone()))
            .configure(http::init_service)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .on_connect(http::request_on_connect_handler);

    if let Some(tls) = tls_config {
        let cert_file: &Path = Path::new(&tls.cert_path);
        let key_file: &Path = Path::new(&tls.key_path);

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder
            .set_private_key_file(key_file, SslFiletype::PEM)
            .map_err(|err| format_err!("unable to read proxy key {} - {}", key_file.display(), err))?;
        builder
            .set_certificate_chain_file(cert_file)
            .map_err(|err| format_err!("unable to read proxy cert {} - {}", cert_file.display(), err))?;
        builder.check_private_key()?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_cipher_list(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:HIGH:!PSK:!SRP:!3DES",
        )?;

        builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);

        http_server = http_server.bind_openssl("127.0.0.1:0", builder)?;
    } else {
        http_server = http_server.bind("127.0.0.1:0")?;
    }

    let addr_info = http_server.addrs().first().unwrap().to_string();

    println!("HTTP Server is running at {}", addr_info);

    Ok((http_server.run(), addr_info))
}

pub fn new_test_http_server_with_prometheus(
    core: Arc<RwLock<Core>>,
    metrics_manager: Arc<RwLock<MetricsManager>>,
    tls_config: Option<TestTlsConfig>,
) -> Result<(Server, String), RvError> {
    let mut http_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(from_fn(metrics_midleware))
            .app_data(web::Data::new(core.clone()))
            .app_data(web::Data::new(Arc::clone(&metrics_manager)))
            .configure(http::init_service)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .on_connect(http::request_on_connect_handler);

    if let Some(tls) = tls_config {
        let cert_file: &Path = Path::new(&tls.cert_path);
        let key_file: &Path = Path::new(&tls.key_path);

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder
            .set_private_key_file(key_file, SslFiletype::PEM)
            .map_err(|err| format_err!("unable to read proxy key {} - {}", key_file.display(), err))?;
        builder
            .set_certificate_chain_file(cert_file)
            .map_err(|err| format_err!("unable to read proxy cert {} - {}", cert_file.display(), err))?;
        builder.check_private_key()?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_cipher_list(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:HIGH:!PSK:!SRP:!3DES",
        )?;

        builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);

        http_server = http_server.bind_openssl("127.0.0.1:0", builder)?;
    } else {
        http_server = http_server.bind("127.0.0.1:0")?;
    }

    let addr_info = http_server.addrs().first().unwrap().to_string();

    println!("HTTP Server is running at {}", addr_info);

    Ok((http_server.run(), addr_info))
}

pub fn start_test_http_server(
    server: Server,
    barrier: Arc<Barrier>,
    stop_rx: oneshot::Receiver<()>,
) -> thread::JoinHandle<()> {
    let server_thread = thread::spawn(move || {
        let sys = actix_web::rt::System::new();

        let server_future = async {
            server.await.unwrap();
        };

        let stop_future = async {
            stop_rx.await.ok();
        };

        barrier.wait();

        let _ = sys.block_on(async {
            tokio::select! {
                _ = server_future => {},
                _ = stop_future => {
                    actix_rt::System::current().stop();
                }
            }
        });

        let _ = sys.run().unwrap();
        println!("HTTP Server has stopped.");
    });

    server_thread
}

pub fn start_test_http_server_with_prometheus(
    server: Server,
    barrier: Arc<Barrier>,
    stop_rx: oneshot::Receiver<()>,
    system_metrics: Arc<SystemMetrics>,
) -> thread::JoinHandle<()> {
    let server_thread = thread::spawn(move || {
        let sys = actix_web::rt::System::new();

        let server_future = async {
            server.await.unwrap();
        };

        let stop_future = async {
            stop_rx.await.ok();
        };

        let system_metrics_fucture = async {
            system_metrics.start_collecting().await;
        };

        barrier.wait();

        let _ = sys.block_on(async {
            tokio::select! {
                _ = server_future => {},
                _ = system_metrics_fucture => {},
                _ = stop_future => {
                    actix_rt::System::current().stop();
                }
            }
        });

        let _ = sys.run().unwrap();
        println!("HTTP Server has stopped.");
    });

    server_thread
}

pub fn test_list_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    println!("list resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    println!("read resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_write_api(
    core: &Core,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = data;

    let resp = core.handle_request(&mut req);
    println!("write resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_delete_api(
    core: &Core,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    req.body = data;
    let resp = core.handle_request(&mut req);
    println!("delete resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_mount_api(core: &Core, token: &str, mtype: &str, path: &str) {
    let data = json!({
        "type": mtype,
    })
    .as_object()
    .unwrap()
    .clone();

    let resp = test_write_api(core, token, format!("sys/mounts/{}", path).as_str(), true, Some(data));
    assert!(resp.is_ok());
}

pub fn test_mount_auth_api(core: &Core, token: &str, atype: &str, path: &str) {
    let auth_data = json!({
        "type": atype,
    })
    .as_object()
    .unwrap()
    .clone();

    let resp = test_write_api(core, token, format!("sys/auth/{}", path).as_str(), true, Some(auth_data));
    assert!(resp.is_ok());
}
