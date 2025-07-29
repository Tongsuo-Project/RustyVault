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
    sync::{Arc, Weak},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use go_defer::defer;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    cli::config::MountEntryHMACLevel,
    errors::RvError,
    handler::{AuthHandler, HandlePhase, Handler},
    logical::{Backend, Request, Response},
    module_manager::ModuleManager,
    modules::auth::AuthModule,
    mount::{
        MountTable, MountsMonitor, MountsRouter, CORE_MOUNT_CONFIG_PATH, LOGICAL_BARRIER_PREFIX, SYSTEM_BARRIER_PREFIX,
    },
    router::Router,
    shamir::{ShamirSecret, SHAMIR_OVERHEAD},
    storage::{
        barrier::SecurityBarrier, barrier_aes_gcm, barrier_view::BarrierView, physical, Backend as PhysicalBackend,
        BackendEntry as PhysicalBackendEntry,
    },
};

pub type LogicalBackendNewFunc = dyn Fn(Arc<Core>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;

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

#[derive(Clone)]
pub struct CoreState {
    pub system_view: Option<Arc<BarrierView>>,
    pub sealed: bool,
    pub unseal_key_shares: Vec<Vec<u8>>,
    pub hmac_key: Vec<u8>,
}

pub struct Core {
    pub self_ptr: Weak<Core>,
    pub physical: Arc<dyn PhysicalBackend>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub mounts_router: Arc<MountsRouter>,
    pub router: Arc<Router>,
    pub handlers: ArcSwap<Vec<Arc<dyn Handler>>>,
    pub auth_handlers: ArcSwap<Vec<Arc<dyn AuthHandler>>>,
    pub module_manager: ModuleManager,
    pub mount_entry_hmac_level: MountEntryHMACLevel,
    pub mounts_monitor: ArcSwapOption<MountsMonitor>,
    pub mounts_monitor_interval: u64,
    pub state: ArcSwap<CoreState>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self { system_view: None, sealed: true, unseal_key_shares: Vec::new(), hmac_key: Vec::new() }
    }
}

impl Default for Core {
    fn default() -> Self {
        let backend: Arc<dyn PhysicalBackend> = Arc::new(physical::mock::MockBackend::new());
        let barrier = Arc::new(barrier_aes_gcm::AESGCMBarrier::new(backend.clone()));
        let router = Arc::new(Router::new());

        Core {
            self_ptr: Weak::new(),
            physical: backend,
            barrier: barrier.clone(),
            router: router.clone(),
            mounts_router: Arc::new(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                router.clone(),
                barrier.clone(),
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            handlers: ArcSwap::from_pointee(vec![router]),
            auth_handlers: ArcSwap::from_pointee(Vec::new()),
            module_manager: ModuleManager::new(),
            mount_entry_hmac_level: MountEntryHMACLevel::None,
            mounts_monitor: ArcSwapOption::empty(),
            mounts_monitor_interval: 5,
            state: ArcSwap::from_pointee(CoreState::default()),
        }
    }
}

#[maybe_async::maybe_async]
impl Core {
    pub fn new(backend: Arc<dyn PhysicalBackend>) -> Self {
        let barrier = Arc::new(barrier_aes_gcm::AESGCMBarrier::new(backend.clone()));
        let router = Arc::new(Router::new());

        Core {
            handlers: ArcSwap::from_pointee(vec![router.clone()]),
            physical: backend,
            barrier: barrier.clone(),
            router: router.clone(),
            mounts_router: Arc::new(MountsRouter::new(
                Arc::new(MountTable::new(CORE_MOUNT_CONFIG_PATH)),
                router,
                barrier,
                LOGICAL_BARRIER_PREFIX,
                "",
            )),
            ..Default::default()
        }
    }

    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    pub fn inited(&self) -> Result<bool, RvError> {
        self.barrier.inited()
    }

    pub fn init(&self, seal_config: &SealConfig) -> Result<InitResult, RvError> {
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

        let barrier = &self.barrier;
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

        let state_old = self.state.load_full();
        let mut state = (*self.state.load_full()).clone();

        state.hmac_key = barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;
        self.state.store(Arc::new(state));

        defer! (
            // Ensure the barrier is re-sealed
            let _ = barrier.seal();
            self.state.store(state_old);
        );

        // Perform initial setup
        self.post_unseal()?;

        // Generate a new root token
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            let te = auth_module.token_store.load().as_ref().unwrap().root_token()?;
            init_result.root_token = te.id;
        } else {
            log::error!("get auth module failed!");
        }

        // Prepare to re-seal
        self.pre_seal()?;

        Ok(init_result)
    }

    pub fn get_system_view(&self) -> Option<Arc<BarrierView>> {
        self.state.load().system_view.clone()
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
        let handlers = self.handlers.load();
        if handlers.iter().any(|h| h.name() == handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        let mut handlers = (*self.handlers.load_full()).clone();

        handlers.push(handler);
        self.handlers.store(Arc::new(handlers));
        Ok(())
    }

    pub fn delete_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let mut handlers = (*self.handlers.load_full()).clone();
        handlers.retain(|h| h.name() != handler.name());
        self.handlers.store(Arc::new(handlers));
        Ok(())
    }

    pub fn add_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let auth_handlers = self.auth_handlers.load();
        if auth_handlers.iter().any(|h| h.name() == auth_handler.name()) {
            return Err(RvError::ErrCoreHandlerExist);
        }

        let mut auth_handlers = (*self.auth_handlers.load_full()).clone();

        auth_handlers.push(auth_handler);
        self.auth_handlers.store(Arc::new(auth_handlers));

        // update auth_module
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            auth_module.set_auth_handlers(self.auth_handlers.load().clone());
        }

        Ok(())
    }

    pub fn delete_auth_handler(&self, auth_handler: Arc<dyn AuthHandler>) -> Result<(), RvError> {
        let mut auth_handlers = (*self.auth_handlers.load_full()).clone();
        auth_handlers.retain(|h| h.name() != auth_handler.name());
        self.auth_handlers.store(Arc::new(auth_handlers));

        // update auth_module
        if let Some(auth_module) = self.module_manager.get_module::<AuthModule>("auth") {
            auth_module.set_auth_handlers(self.auth_handlers.load().clone());
        }

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
        self.state.load().sealed
    }

    pub fn unseal_progress(&self) -> usize {
        self.state.load().unseal_key_shares.len()
    }

    pub fn unseal(&self, key: &[u8]) -> Result<bool, RvError> {
        let inited = self.barrier.inited()?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = self.barrier.sealed()?;
        if !sealed {
            return Err(RvError::ErrBarrierUnsealed);
        }

        let (min, mut max) = self.barrier.key_length_range();
        max += SHAMIR_OVERHEAD;
        if key.len() < min || key.len() > max {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let state_old = self.state.load_full();
        let mut state = (*self.state.load_full()).clone();
        let config = self.seal_config()?;
        if state.unseal_key_shares.iter().any(|v| *v == key) {
            return Ok(false);
        }

        state.unseal_key_shares.push(key.to_vec());
        if state.unseal_key_shares.len() < config.secret_threshold as usize {
            self.state.store(Arc::new(state));
            return Ok(false);
        }

        let master_key: Vec<u8>;
        if config.secret_threshold == 1 {
            master_key = state.unseal_key_shares[0].clone();
            state.unseal_key_shares.clear();
        } else if let Some(res) = ShamirSecret::combine(state.unseal_key_shares.clone()) {
            master_key = res;
            state.unseal_key_shares.clear();
        } else {
            //TODO
            state.unseal_key_shares.clear();
            self.state.store(Arc::new(state));
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        log::debug!("unseal, recover master_key: {}", hex::encode(&master_key));
        // Unseal the barrier
        self.barrier.unseal(master_key.as_slice())?;

        state.hmac_key = self.barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(self.barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;

        self.state.store(Arc::new(state));

        // Perform initial setup
        if let Err(e) = self.post_unseal() {
            self.state.store(state_old);
            return Err(e);
        }

        Ok(true)
    }

    pub fn seal(&self, _token: &str) -> Result<(), RvError> {
        let inited = self.barrier.inited()?;
        if !inited {
            return Err(RvError::ErrBarrierNotInit);
        }

        let sealed = self.barrier.sealed()?;
        if sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        self.pre_seal()?;

        let mut state = (*self.state.load_full()).clone();
        state.sealed = true;
        state.system_view = None;
        state.unseal_key_shares.clear();
        state.hmac_key.clear();
        self.state.store(Arc::new(state));

        self.barrier.seal()
    }

    fn post_unseal(&self) -> Result<(), RvError> {
        self.module_manager.setup(self)?;

        // Perform initial setup
        self.mounts_router.load_or_default(
            self.barrier.as_storage(),
            Some(&self.state.load().hmac_key),
            self.mount_entry_hmac_level,
        )?;

        self.mounts_router.setup(self.self_ptr.upgrade().unwrap().clone())?;

        self.module_manager.init(self)?;

        if let Some(mounts_monitor) = self.mounts_monitor.load().as_ref() {
            mounts_monitor.add_mounts_router(self.mounts_router.clone());
            mounts_monitor.start();
        }

        Ok(())
    }

    fn pre_seal(&self) -> Result<(), RvError> {
        if let Some(mounts_monitor) = self.mounts_monitor.load().as_ref() {
            mounts_monitor.remove_mounts_router(self.mounts_router.clone());
            mounts_monitor.stop();
        }
        self.module_manager.cleanup(self)?;
        self.unload_mounts()?;
        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = None;
        let mut err: Option<RvError> = None;
        let handlers = self.handlers.load();

        if self.state.load().sealed {
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
    use crate::test_utils::new_unseal_test_rusty_vault;

    #[test]
    fn test_core_init() {
        let _ = new_unseal_test_rusty_vault("test_core_init");
    }
}
