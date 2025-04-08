//! The `rusty_vault::core` module implements several key functions that are
//! in charge of the whole process of RustyVault. For instance, to seal or unseal the RustyVault we
//! have the `seal()` and `unseal()` functions in this module. Also, the `handle_request()`
//! function in this module is to route an API call to its correct backend and get the result back
//! to the caller.
//!
//! This module is very low-level and usually it should not disturb end users and module developers
//! of RustyVault.

use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock},
};

use as_any::Downcast;
use go_defer::defer;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    cli::config::{Config, MountEntryHMACLevel},
    errors::RvError,
    handler::{AuthHandler, HandlePhase, Handler},
    logical::{Backend, Request, Response},
    module_manager::ModuleManager,
    modules::{
        auth::AuthModule,
        credential::{approle::AppRoleModule, cert::CertModule, userpass::UserPassModule},
        pki::PkiModule,
        policy::PolicyModule,
    },
    mount::{
        MountTable, MountsMonitor, MountsRouter, CORE_MOUNT_CONFIG_PATH, LOGICAL_BARRIER_PREFIX, SYSTEM_BARRIER_PREFIX,
    },
    router::Router,
    shamir::{ShamirSecret, SHAMIR_OVERHEAD},
    storage::{
        barrier::SecurityBarrier, barrier_aes_gcm, barrier_view::BarrierView, physical, Backend as PhysicalBackend,
        BackendEntry as PhysicalBackendEntry, Storage,
    },
};

pub type LogicalBackendNewFunc = dyn Fn(Arc<RwLock<Core>>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;

pub const SEAL_CONFIG_PATH: &str = "core/seal-config";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealConfig {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

impl SealConfig {
    pub fn validate(&self) -> Result<(), RvError> {
        if self.secret_threshold > self.secret_shares {
            return Err(RvError::ErrCoreSealConfigInvalid);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InitResult {
    pub secret_shares: Zeroizing<Vec<Vec<u8>>>,
    pub root_token: String,
}

pub struct Core {
    pub self_ref: Option<Arc<RwLock<Core>>>,
    pub physical: Arc<dyn PhysicalBackend>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub system_view: Option<Arc<BarrierView>>,
    pub handlers: RwLock<Vec<Arc<dyn Handler>>>,
    pub auth_handlers: Arc<RwLock<Vec<Arc<dyn AuthHandler>>>>,
    pub router: Arc<Router>,
    pub mounts_router: Arc<MountsRouter>,
    pub module_manager: ModuleManager,
    pub sealed: bool,
    pub unseal_key_shares: Vec<Vec<u8>>,
    pub hmac_key: Vec<u8>,
    pub mount_entry_hmac_level: MountEntryHMACLevel,
    pub mounts_monitor: Option<MountsMonitor>,
    pub mounts_monitor_interval: u64,
}

impl Default for Core {
    fn default() -> Self {
        let backend: Arc<dyn PhysicalBackend> = Arc::new(physical::mock::MockBackend::new());
        let barrier = Arc::new(barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend)));
        let barrier_cloned = Arc::clone(&barrier);
        let router = Arc::new(Router::new());

        Core {
            self_ref: None,
            physical: backend,
            barrier: barrier_cloned,
            system_view: None,
            router: Arc::clone(&router),
            mounts_router: Arc::new(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                Arc::clone(&router),
                barrier,
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            handlers: RwLock::new(vec![router]),
            auth_handlers: Arc::new(RwLock::new(Vec::new())),
            module_manager: ModuleManager::new(),
            sealed: true,
            unseal_key_shares: Vec::new(),
            hmac_key: Vec::new(),
            mount_entry_hmac_level: MountEntryHMACLevel::None,
            mounts_monitor: None,
            mounts_monitor_interval: 5,
        }
    }
}

#[maybe_async::maybe_async]
impl Core {
    pub fn new(backend: Arc<dyn PhysicalBackend>) -> Self {
        let barrier = Arc::new(barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend)));
        let barrier_cloned = Arc::clone(&barrier);
        let router = Arc::new(Router::new());

        Core {
            physical: backend,
            barrier: barrier_cloned,
            router: Arc::clone(&router),
            mounts_router: Arc::new(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                Arc::clone(&router),
                barrier,
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            handlers: RwLock::new(vec![router]),
            ..Default::default()
        }
    }

    pub fn config(&mut self, core: Arc<RwLock<Core>>, config: Option<&Config>) -> Result<(), RvError> {
        if let Some(conf) = config {
            self.mount_entry_hmac_level = conf.mount_entry_hmac_level;
            self.mounts_monitor_interval = conf.mounts_monitor_interval;
        }

        self.module_manager.set_default_modules(Arc::clone(&core))?;
        self.self_ref = Some(Arc::clone(&core));

        // add auth_module
        let auth_module = AuthModule::new(self)?;
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(auth_module))))?;

        // add policy_module
        let policy_module = PolicyModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(policy_module))))?;

        // add pki_module
        let pki_module = PkiModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(pki_module))))?;

        // add credential module: userpass
        let userpass_module = UserPassModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(userpass_module))))?;

        // add credential module: approle
        let approle_module = AppRoleModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(approle_module))))?;

        // add credential module: cert
        let cert_module = CertModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(cert_module))))?;

        self.mounts_monitor = Some(MountsMonitor::new(core, self.mounts_monitor_interval));

        let handlers = { self.handlers.read()?.clone() };
        for handler in handlers.iter() {
            match handler.post_config(self, config) {
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

        Ok(())
    }

    pub fn inited(&self) -> Result<bool, RvError> {
        self.barrier.inited()
    }

    pub fn init(&mut self, seal_config: &SealConfig) -> Result<InitResult, RvError> {
        let inited = self.inited()?;
        if inited {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        seal_config.validate()?;

        // Encode the seal configuration
        let serialized_seal_config = serde_json::to_string(seal_config)?;

        // Store the seal configuration
        let pe = PhysicalBackendEntry {
            key: SEAL_CONFIG_PATH.to_string(),
            value: serialized_seal_config.as_bytes().to_vec(),
        };
        self.physical.put(&pe)?;

        let barrier = Arc::clone(&self.barrier);
        // Generate a master key
        // The newly generated master key will be zeroized on drop.
        let master_key = barrier.generate_key()?;

        // Initialize the barrier
        barrier.init(master_key.deref().as_slice())?;

        let mut init_result = InitResult { secret_shares: Zeroizing::new(Vec::new()), root_token: String::new() };

        if seal_config.secret_shares == 1 {
            init_result.secret_shares.deref_mut().push(master_key.deref().clone());
        } else {
            init_result.secret_shares = ShamirSecret::split(
                master_key.deref().as_slice(),
                seal_config.secret_shares,
                seal_config.secret_threshold,
            )?;
        }

        log::debug!("master_key: {}", hex::encode(master_key.deref()));
        log::debug!("seal config: {:?}", seal_config);
        log::debug!("secret_shares:");
        for key in init_result.secret_shares.iter() {
            log::debug!("{}", hex::encode(key));
        }

        // Unseal the barrier
        barrier.unseal(master_key.deref().as_slice())?;

        defer! (
            // Ensure the barrier is re-sealed
            let _ = barrier.seal();
        );

        // Perform initial setup
        self.post_unseal()?;

        // Generate a new root token
        if let Some(module) = self.module_manager.get_module("auth") {
            let auth_mod = module.read()?;
            if let Some(auth_module) = auth_mod.as_ref().downcast_ref::<AuthModule>() {
                let te = auth_module.token_store.as_ref().unwrap().root_token()?;
                init_result.root_token = te.id;
            } else {
                log::error!("downcast auth module failed!");
            }
        } else {
            log::error!("get auth module failed!");
        }

        // Prepare to re-seal
        self.pre_seal()?;

        Ok(init_result)
    }

    pub fn get_system_view(&self) -> Option<Arc<BarrierView>> {
        self.system_view.clone()
    }

    pub fn get_system_storage(&self) -> &dyn Storage {
        self.system_view.as_ref().unwrap().as_storage()
    }

    pub fn get_logical_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        self.mounts_router.get_backend(logical_type)
    }

    pub fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        self.mounts_router.add_backend(logical_type, backend)
    }

    pub fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        self.mounts_router.delete_backend(logical_type)
    }

    pub fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let mut handlers = self.handlers.write()?;
        if handlers.iter().any(|h| h.name() == handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        handlers.push(handler);
        Ok(())
    }

    pub fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let mut handlers = self.handlers.write()?;
        handlers.retain(|h| h.name() != handler.name());
        Ok(())
    }

    pub fn add_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let mut auth_handlers = self.auth_handlers.write()?;
        if auth_handlers.iter().any(|h| h.name() == auth_handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        auth_handlers.push(auth_handler);
        Ok(())
    }

    pub fn delete_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let mut auth_handlers = self.auth_handlers.write()?;
        auth_handlers.retain(|h| h.name() != auth_handler.name());
        Ok(())
    }

    pub fn seal_config(&self) -> Result<SealConfig, RvError> {
        let pe = self.physical.get(SEAL_CONFIG_PATH)?;

        if pe.is_none() {
            return Err(RvError::ErrCoreSealConfigNotFound);
        }

        let config: SealConfig = serde_json::from_slice(pe.unwrap().value.as_slice())?;
        config.validate()?;
        Ok(config)
    }

    pub fn sealed(&self) -> bool {
        self.sealed
    }

    pub fn unseal_progress(&self) -> usize {
        self.unseal_key_shares.len()
    }

    pub fn unseal(&mut self, key: &[u8]) -> Result<bool, RvError> {
        let barrier = Arc::clone(&self.barrier);

        let inited = barrier.inited()?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = barrier.sealed()?;
        if !sealed {
            return Err(RvError::ErrBarrierUnsealed);
        }

        let (min, mut max) = self.barrier.key_length_range();
        max += SHAMIR_OVERHEAD;
        if key.len() < min || key.len() > max {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let config = self.seal_config()?;
        if self.unseal_key_shares.iter().any(|v| *v == key) {
            return Ok(false);
        }

        self.unseal_key_shares.push(key.to_vec());
        if self.unseal_key_shares.len() < config.secret_threshold as usize {
            return Ok(false);
        }

        let master_key: Vec<u8>;
        if config.secret_threshold == 1 {
            master_key = self.unseal_key_shares[0].clone();
            self.unseal_key_shares.clear();
        } else if let Some(res) = ShamirSecret::combine(self.unseal_key_shares.clone()) {
            master_key = res;
            self.unseal_key_shares.clear();
        } else {
            //TODO
            self.unseal_key_shares.clear();
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        log::debug!("unseal, recover master_key: {}", hex::encode(&master_key));
        // Unseal the barrier
        barrier.unseal(master_key.as_slice())?;

        // Perform initial setup
        self.post_unseal()?;

        self.sealed = false;

        Ok(true)
    }

    pub fn seal(&mut self, _token: &str) -> Result<(), RvError> {
        let barrier = Arc::clone(&self.barrier);

        let inited = barrier.inited()?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = barrier.sealed()?;
        if sealed {
            return Err(RvError::ErrBarrierSealed);
        }
        self.pre_seal()?;
        self.sealed = true;
        barrier.seal()
    }

    fn post_unseal(&mut self) -> Result<(), RvError> {
        self.module_manager.setup(self)?;

        // Perform initial setup
        self.hmac_key = self.barrier.derive_hmac_key()?;
        self.mounts_router.load_or_default(
            self.barrier.as_storage(),
            Some(&self.hmac_key),
            self.mount_entry_hmac_level,
        )?;

        self.mounts_router.setup(self.self_ref.as_ref().unwrap())?;

        self.system_view = Some(Arc::new(BarrierView::new(self.barrier.clone(), SYSTEM_BARRIER_PREFIX)));

        self.module_manager.init(self)?;

        self.mounts_monitor.as_ref().unwrap().add_mounts_router(self.mounts_router.clone());
        self.mounts_monitor.as_mut().unwrap().start();

        Ok(())
    }

    fn pre_seal(&mut self) -> Result<(), RvError> {
        self.mounts_monitor.as_ref().unwrap().remove_mounts_router(self.mounts_router.clone());
        self.mounts_monitor.as_mut().unwrap().stop();
        self.module_manager.cleanup(self)?;
        self.unload_mounts()?;
        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = None;
        let mut err: Option<RvError> = None;
        let handlers = self.handlers.read()?;

        if self.sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        match self.handle_pre_route_phase(&handlers, req).await {
            Ok(ret) => resp = ret,
            Err(e) => err = Some(e),
        }

        if resp.is_none() && err.is_none() {
            match self.handle_route_phase(&handlers, req).await {
                Ok(ret) => resp = ret,
                Err(e) => err = Some(e),
            }

            if err.is_none() {
                if let Err(e) = self.handle_post_route_phase(&handlers, req, &mut resp).await {
                    err = Some(e)
                }
            }
        }

        if err.is_none() {
            self.handle_log_phase(&handlers, req, &mut resp).await?;
        }

        if err.is_some() {
            return Err(err.unwrap());
        }

        Ok(resp)
    }

    async fn handle_pre_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.handle_phase = HandlePhase::PreRoute;
        for handler in handlers.iter() {
            match handler.pre_route(req).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(None)
    }

    async fn handle_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.handle_phase = HandlePhase::Route;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.route(req).await {
                Ok(res) => return Ok(res),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.route(req).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(None)
    }

    async fn handle_post_route_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        req.handle_phase = HandlePhase::PostRoute;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.post_route(req, resp).await {
                Ok(_) => return Ok(()),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.post_route(req, resp).await {
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(())
    }

    async fn handle_log_phase(
        &self,
        handlers: &Vec<Arc<dyn Handler>>,
        req: &mut Request,
        resp: &mut Option<Response>,
    ) -> Result<(), RvError> {
        req.handle_phase = HandlePhase::Log;
        if let Some(bind_handler) = req.get_handler() {
            match bind_handler.log(req, resp).await {
                Ok(_) => return Ok(()),
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => {}
            }
        }

        for handler in handlers.iter() {
            match handler.log(req, resp).await {
                Err(e) if e != RvError::ErrHandlerDefault => return Err(e),
                _ => continue,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::init_test_rusty_vault;

    #[test]
    fn test_core_init() {
        let _ = init_test_rusty_vault("test_core_init");
    }
}
