//! This module provides different commands for the RustyVault application.
//! For instance, we have a 'server' command to indicate the application running in the server mode
//! and starts to accept HTTP request to do real RustyVault functionality.

use std::{
    fs,
    path::PathBuf,
    io::BufReader,
    sync::Arc,
    time::Duration,
};

use serde_json::{json, Map, Value, to_string_pretty};
use serde_yaml::to_string;
use clap::{Args, ArgAction, ValueEnum, ValueHint};
use ureq::AgentBuilder;
use rustls::{
    pki_types::{PrivateKeyDer, pem::PemObject},
    ALL_VERSIONS, ClientConfig, RootCertStore,
};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    errors::RvError,
    utils::cert::DisabledVerifier,
};

pub mod server;
pub mod status;
pub mod operator;
pub mod operator_init;
pub mod operator_seal;
pub mod operator_unseal;

#[derive(Args, Default)]
#[group(required = false, multiple = true)]
pub struct HttpOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        default_value = "https://127.0.0.1:8200",
        long_help = r#"Address of the RustyVault server. This can also be specified via the
VAULT_ADDR or RUSTY_VAULT_ADDR environment variable."#
    )]
    address: String,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CACERT",
        long_help = r#"Path on the local disk to a single PEM-encoded CA certificate to verify
the RustyVault server's SSL certificate. This takes precedence over -ca-path.
This can also be specified via the VAULT_CACERT environment variable."#
    )]
    ca_cert: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::DirPath,
        env = "VAULT_CAPATH",
        long_help = r#"Path on the local disk to a directory of PEM-encoded CA certificates to
verify the RustyVault server's SSL certificate. This can also be specified
via the VAULT_CAPATH environment variable."#
    )]
    ca_path: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CLIENT_CERT",
        long_help = r#"Path on the local disk to a single PEM-encoded CA certificate to use
for TLS authentication to the Vault server. If this flag is specified,
-client-key is also required. This can also be specified via the VAULT_CLIENT_CERT
environment variable."#
    )]
    client_cert: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        value_hint = ValueHint::FilePath,
        env = "VAULT_CLIENT_KEY",
        long_help = r#"Path on the local disk to a single PEM-encoded private key matching the
client certificate from -client-cert. This can also be specified via the
VAULT_CLIENT_KEY environment variable."#
    )]
    client_key: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        long_help = r#"Name to use as the SNI host when connecting to the Vault server via TLS.
This can also be specified via the VAULT_TLS_SERVER_NAME environment variable."#
    )]
    tls_server_name: Option<String>,

    #[arg(
        long,
        next_line_help = true,
        env = "VAULT_SKIP_VERIFY",
        long_help = r#"Disable verification of TLS certificates. Using this option is highly
discouraged as it decreases the security of data transmissions to and
from the RustyVault server. The default is false. This can also be specified
via the VAULT_SKIP_VERIFY environment variable."#
    )]
    tls_skip_verify: bool,

    #[clap(
        long,
        value_name = "key=value",
        action = ArgAction::Append,
        long_help = r#"Key-value pair provided as key=value to provide http header added to any
request done by the CLI. Trying to add headers starting with 'X-Vault-'
is forbidden and will make the command fail. This can be specified multiple times.
        "#
    )]
    header: Vec<String>,

    #[clap(
        hide = true,
        required = false,
        env = "VAULT_TOKEN",
        default_value = "",
    )]
    token: String,
}

#[derive(Args)]
#[group(required = false, multiple = true)]
pub struct CommandOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        long_help = r#"Path to a configuration file or directory of configuration files. This
flag can be specified multiple times to load multiple configurations.
If the path is a directory, all files which end in .hcl or .json are loaded."#
    )]
    config: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        default_value = "false",
        long_help = "Path to the log file that Vault should use for logging"
    )]
    log_file: Option<PathBuf>,

    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        num_args = 0..=1,
        env = "VAULT_LOG_LEVEL",
        default_value_t = LogLevel::Warn,
        default_missing_value = "error",
        long_help = r#"Log verbosity level. This can also be specified via the VAULT_LOG_LEVEL
or RUSTY_VAULT_LOG_LEVEL environment variable.
"#,
        value_enum
    )]
    log_level: LogLevel,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Args)]
#[group(required = false, multiple = true)]
pub struct OutputOptions {
    #[arg(
        long,
        next_line_help = true,
        value_name = "string",
        num_args = 0..=1,
        env = "VAULT_FORMAT",
        default_value_t = Format::Table,
        default_missing_value = "table",
        long_help = r#"Print the output in the given format.  This can also be specified via the
VAULT_FORMAT environment variable."#,
        value_enum
    )]
    format: Format,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    Yaml,
    Raw,
}

impl HttpOptions {
    pub fn init(&mut self) -> Result<(), RvError> {
        Ok(())
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        data: Option<Map<String, Value>>
    ) -> Result<(u16, Value), RvError> {
        let url = if path.starts_with("/") {
            format!("{}{}", self.address, path)
        } else {
            format!("{}/{}", self.address, path)
        };
        println!("request url: {}, method: {}", url, method);
        let mut req = if url.starts_with("https") {
/*
            let _ = rustls::crypto::ring::default_provider().install_default();
            let builder = ClientConfig::builder();
*/
            let provider = rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or(Arc::new(rustls::crypto::ring::default_provider()));

                //.with_protocol_versions(&[&rustls::version::TLS12])
            let builder = ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(ALL_VERSIONS)
                .expect("all TLS versions");

            let builder = if self.tls_skip_verify {
                log::debug!("Certificate verification disabled");
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
            } else {
                if let Some(ca_cert) = &self.ca_cert {
                    let cert_data = fs::read(ca_cert)?;
                    let mut cert_reader = BufReader::new(&cert_data[..]);
                    let root_certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

                    let mut root_store = RootCertStore::empty();
                    let (added, ignored) = root_store.add_parsable_certificates(root_certs);
                    log::debug!("Added {} and ignored {} root certs", added, ignored);
                    builder.with_root_certificates(root_store)
                } else {
                    let root_store = RootCertStore {
                        roots: TLS_SERVER_ROOTS.to_vec(),
                    };
                    builder.with_root_certificates(root_store)
                }
            };

            // Create rustls ClientConfig
            let tls_config = if let (Some(client_cert), Some(client_key)) = (&self.client_cert, &self.client_key) {
                let cert_data = fs::read(client_cert)?;
                let mut cert_reader = BufReader::new(&cert_data[..]);
                let client_certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
                let client_key = PrivateKeyDer::from_pem_file(&client_key)?;

                builder.with_client_auth_cert(client_certs, client_key)?
            } else {
                builder.with_no_client_auth()
            };

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
            req = req.set("X-RustyVault-Token", &self.token);
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
                log::error!("Request failed: {}", e);
                return Err(RvError::UreqError { source: e });
            }
        }
    }

    pub fn request_list(&self, path: &str) -> Result<(u16, Value), RvError> {
        self.request("LIST", path, None)
    }

    pub fn request_read(&self, path: &str) -> Result<(u16, Value), RvError> {
        self.request("GET", path, None)
    }

    pub fn request_write(&self, path: &str, data: Option<Map<String, Value>>,
    ) -> Result<(u16, Value), RvError> {
        self.request("POST", path, data)
    }

    pub fn request_delete(&self, path: &str, data: Option<Map<String, Value>>) -> Result<(u16, Value), RvError> {
        self.request("DELETE", path, data)
    }
}

impl OutputOptions {
    pub fn print_value(&self, value: &Value) -> Result<(), RvError> {
        println!("format: {:?}", self.format);
        match self.format {
            Format::Json => {
                println!("json:");
                println!("{}", to_string_pretty(value)?);
            }
            Format::Yaml => {
                println!("yaml:");
                println!("{}", to_string(value)?);
            }
            Format::Table => {
                println!("table:");
            }
            Format::Raw => {
                println!("raw:");
            }
        }

        Ok(())
    }
}
