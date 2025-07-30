//! This crate is the 'library' part of RustyVault, a Rust and real free replica of Hashicorp Vault.
//! RustyVault is focused on identity-based secrets management and works in two ways independently:
//!
//! 1. A standalone application serving secrets management via RESTful API;
//! 2. A Rust crate that provides same features for other application to integrate.
//!
//! This document is only about the crate part of RustyVault. For the first working mode,
//! please go to RustyVault's [RESTful API documentation], which documents all RustyVault's RESTful API.
//! Users can use an HTTP client tool (curl, e.g.) to send commands to a running RustyVault server and
//! then have relevant secret management features.
//!
//! The second working mode, which works as a typical Rust crate called `rusty_vault`, allows Rust
//! application developers to integrate RustyVault easily into their own applications to have the
//! ability of secrets management such as secure key/vaule storage, public key cryptography, data
//! encryption and so forth.
//!
//! This is the official documentation of crate `rusty_vault`, and it's mainly for developers.
//! Once again, if you are looking for how to use the RustyVault server via a set of RESTful API,
//! then you may prefer the RustyVault's [RESTful API documentation].
//!
//! [Hashicorp Vault]: https://www.hashicorp.com/products/vault
//! [RESTful API documentation]: https://www.tongsuo.net

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::{Map, Value};

use crate::{
    cli::config::Config,
    core::Core,
    errors::RvError,
    logical::{Request, Response},
    modules::{
        auth::AuthModule,
        credential::{approle::AppRoleModule, cert::CertModule, userpass::UserPassModule},
        pki::PkiModule,
        policy::PolicyModule,
    },
    mount::MountsMonitor,
    storage::Backend,
};

#[cfg(feature = "storage_mysql")]
extern crate diesel;

pub mod api;
pub mod cli;
pub mod context;
pub mod core;
pub mod errors;
pub mod handler;
pub mod http;
pub mod logical;
pub mod metrics;
pub mod module_manager;
pub mod modules;
pub mod mount;
pub mod router;
#[cfg(feature = "storage_mysql")]
pub mod schema;
pub mod shamir;
pub mod storage;
pub mod utils;

#[cfg(test)]
pub mod test_utils;

/// Exit ok
pub const EXIT_CODE_OK: sysexits::ExitCode = sysexits::ExitCode::Ok;
/// Exit code when server exits unexpectedly
pub const EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when server aborted
pub const EXIT_CODE_SERVER_ABORTED: sysexits::ExitCode = sysexits::ExitCode::Software;
/// Exit code when loading configuration from file fails
pub const EXIT_CODE_LOAD_CONFIG_FAILURE: sysexits::ExitCode = sysexits::ExitCode::Config;
/// Exit code when insufficient params are passed via CLI
pub const EXIT_CODE_INSUFFICIENT_PARAMS: sysexits::ExitCode = sysexits::ExitCode::Usage;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// rusty_vault version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct RustyVault {
    pub core: ArcSwap<Core>,
    pub token: String,
}

#[maybe_async::maybe_async]
impl RustyVault {
    pub fn new(backend: Arc<dyn Backend>, config: Option<&Config>) -> Result<Self, RvError> {
        let mut core = Core::new(backend);
        if let Some(conf) = config {
            core.mount_entry_hmac_level = conf.mount_entry_hmac_level;
            core.mounts_monitor_interval = conf.mounts_monitor_interval;
        }

        let core = core.wrap();

        core.mounts_monitor.store(Some(Arc::new(MountsMonitor::new(core.clone(), core.mounts_monitor_interval))));

        core.module_manager.set_default_modules(core.clone())?;

        // add auth_module
        let auth_module = AuthModule::new(core.clone())?;
        core.module_manager.add_module(Arc::new(auth_module))?;

        // add policy_module
        let policy_module = PolicyModule::new(core.clone());
        core.module_manager.add_module(Arc::new(policy_module))?;

        // add pki_module
        let pki_module = PkiModule::new(core.clone());
        core.module_manager.add_module(Arc::new(pki_module))?;

        // add credential module: userpass
        let userpass_module = UserPassModule::new(core.clone());
        core.module_manager.add_module(Arc::new(userpass_module))?;

        // add credential module: approle
        let approle_module = AppRoleModule::new(core.clone());
        core.module_manager.add_module(Arc::new(approle_module))?;

        // add credential module: cert
        let cert_module = CertModule::new(core.clone());
        core.module_manager.add_module(Arc::new(cert_module))?;

        let handlers = core.handlers.load().clone();
        for handler in handlers.iter() {
            match handler.post_config(core.clone(), config) {
                Ok(_) => {
                    continue;
                }
                Err(error) => {
                    if error != RvError::ErrHandlerDefault {
                        return Err(error);
                    }
                }
            }
        }

        Ok(Self { core: ArcSwap::new(core), token: String::new() })
    }

    pub fn init(&self, seal_config: &core::SealConfig) -> Result<core::InitResult, RvError> {
        self.core.load().init(seal_config)
    }

    pub fn unseal(&self, key: &[u8]) -> Result<bool, RvError> {
        self.core.load().unseal(key)
    }

    pub fn seal(&self, token: &str) -> Result<(), RvError> {
        self.core.load().seal(token)
    }

    pub async fn mount(&self, path: &str, mount_type: &str) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "type": mount_type,
        })
        .as_object()
        .cloned();

        self.write(format!("sys/mounts/{path}").as_str(), data).await
    }

    pub async fn unmount(&self, path: &str) -> Result<Option<Response>, RvError> {
        self.delete(format!("sys/mounts/{path}").as_str(), None).await
    }

    pub async fn remount(&self, from: &str, to: &str) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "from": from,
            "to": to,
        })
        .as_object()
        .cloned();

        self.write("sys/remount", data).await
    }

    pub async fn enable_auth(&self, path: &str, auth_type: &str) -> Result<Option<Response>, RvError> {
        let data = serde_json::json!({
            "type": auth_type,
        })
        .as_object()
        .cloned();

        self.write(format!("sys/auth/{path}").as_str(), data).await
    }

    pub async fn disable_auth(&self, path: &str) -> Result<Option<Response>, RvError> {
        self.delete(format!("sys/auth/{path}").as_str(), None).await
    }

    pub async fn login(
        &mut self,
        path: &str,
        data: Option<Map<String, Value>>,
    ) -> Result<(Option<Response>, bool), RvError> {
        let mut login_success = false;
        let mut req = Request::new_write_request(path, data);
        let resp = self.core.load().handle_request(&mut req).await?;
        if let Some(response) = resp.as_ref() {
            if let Some(auth) = response.auth.as_ref() {
                self.token = auth.client_token.clone();
                login_success = true;
            }
        }

        Ok((resp, login_success))
    }

    pub async fn request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        req.client_token = self.token.to_string();
        self.core.load().handle_request(req).await
    }

    pub async fn read(&self, path: &str) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_read_request(path);
        self.request(&mut req).await
    }

    pub async fn write(&self, path: &str, data: Option<Map<String, Value>>) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_write_request(path, data);
        self.request(&mut req).await
    }

    pub async fn delete(&self, path: &str, data: Option<Map<String, Value>>) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_delete_request(path, data);
        self.request(&mut req).await
    }

    pub async fn list(&self, path: &str) -> Result<Option<Response>, RvError> {
        let mut req = Request::new_list_request(path);
        self.request(&mut req).await
    }
}
