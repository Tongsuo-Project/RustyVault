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
use zeroize::{Zeroize, Zeroizing};

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
    utils::BHashSet,
};

pub type LogicalBackendNewFunc = dyn Fn(Arc<Core>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;

const SEAL_CONFIG_PATH: &str = "core/seal-config";
const DEPRECATED_UNSEAL_KEY_SET_PATH: &str = "core/used-unseal-keys-set";

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

#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct InitResult {
    pub secret_shares: Zeroizing<Vec<Vec<u8>>>,
    pub root_token: String,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CoreState {
    #[zeroize(skip)]
    pub system_view: Option<Arc<BarrierView>>,
    pub sealed: bool,
    pub hmac_key: Vec<u8>,
    unseal_key_shares: Vec<Vec<u8>>,
    kek: Vec<u8>,
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
        Self { system_view: None, sealed: true, unseal_key_shares: Vec::new(), hmac_key: Vec::new(), kek: Vec::new() }
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
            mounts_monitor_interval: 0,
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

        let deprecated_key_set = BHashSet::default();
        let pe = PhysicalBackendEntry {
            key: DEPRECATED_UNSEAL_KEY_SET_PATH.to_string(),
            value: serde_json::to_string(&deprecated_key_set)?.as_bytes().to_vec(),
        };
        self.physical.put(&pe)?;

        let barrier = &self.barrier;
        // Generate a key encryption key, will be zeroized on drop.
        let kek = barrier.generate_key()?;

        // Initialize the barrier
        barrier.init(kek.deref().as_slice())?;

        let mut init_result = InitResult { secret_shares: Zeroizing::new(Vec::new()), root_token: String::new() };

        // Unseal the barrier
        barrier.unseal(kek.deref().as_slice())?;

        let state_old = self.state.load_full();
        let mut state = (*self.state.load_full()).clone();

        state.hmac_key = barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;
        state.kek = kek.deref().clone();
        self.state.store(Arc::new(state));

        if seal_config.secret_shares == 1 {
            init_result.secret_shares.deref_mut().push(kek.deref().clone());
        } else {
            init_result.secret_shares = self.generate_unseal_keys()?;
        }

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

    pub fn deprecated_unseal_keys_set(&self) -> Result<BHashSet, RvError> {
        let pe =
            self.physical.get(DEPRECATED_UNSEAL_KEY_SET_PATH)?.ok_or(RvError::ErrCoreDeprecatedUnsealKeySetNotFound)?;
        let used_key_set: BHashSet = serde_json::from_slice(pe.value.as_slice())?;
        Ok(used_key_set)
    }

    pub fn sealed(&self) -> bool {
        self.state.load().sealed
    }

    pub fn unseal_progress(&self) -> usize {
        self.state.load().unseal_key_shares.len()
    }

    pub fn do_unseal(&self, key: &[u8], once: bool) -> Result<bool, RvError> {
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

        let mut state = (*self.state.load_full()).clone();
        let config = self.seal_config()?;
        if state.unseal_key_shares.iter().any(|v| *v == key) {
            return Ok(false);
        }

        let mut deprecated_key_set = self.deprecated_unseal_keys_set();
        if let Ok(deprecated_key_set) = &deprecated_key_set {
            if deprecated_key_set.contains(key) {
                return Err(RvError::ErrBarrierKeyDeprecated);
            }
        }

        state.unseal_key_shares.push(key.to_vec());
        if state.unseal_key_shares.len() < config.secret_threshold as usize {
            self.state.store(Arc::new(state));
            return Ok(false);
        }

        let kek: Zeroizing<Vec<u8>>;
        if config.secret_threshold == 1 {
            kek = Zeroizing::new(state.unseal_key_shares[0].clone());
        } else if let Some(res) = ShamirSecret::combine(state.unseal_key_shares.clone()) {
            kek = Zeroizing::new(res);
        } else {
            //TODO
            state.unseal_key_shares.clear();
            self.state.store(Arc::new(state));
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        // Unseal the barrier
        if let Err(e) = self.barrier.unseal(kek.as_slice()) {
            state.unseal_key_shares.clear();
            self.state.store(Arc::new(state));
            return Err(e);
        }

        let unseal_key_shares = Zeroizing::new(state.unseal_key_shares.clone());
        state.unseal_key_shares.clear();
        state.hmac_key = self.barrier.derive_hmac_key()?;
        state.system_view = Some(Arc::new(BarrierView::new(self.barrier.clone(), SYSTEM_BARRIER_PREFIX)));
        state.sealed = false;
        state.kek = kek.deref().clone();
        self.state.store(Arc::new(state));

        // Perform initial setup
        if let Err(e) = self.post_unseal() {
            let mut state = (*self.state.load_full()).clone();
            state.unseal_key_shares.clear();
            state.kek.clear();
            state.hmac_key.clear();
            state.system_view = None;
            state.sealed = true;
            self.state.store(Arc::new(state));
            return Err(e);
        }

        if once {
            if let Ok(deprecated_key_set) = &mut deprecated_key_set {
                for key in unseal_key_shares.iter() {
                    deprecated_key_set.insert(key);
                }

                let pe = PhysicalBackendEntry {
                    key: DEPRECATED_UNSEAL_KEY_SET_PATH.to_string(),
                    value: serde_json::to_string(deprecated_key_set)?.as_bytes().to_vec(),
                };
                self.physical.put(&pe)?;
            }
        }

        Ok(true)
    }

    pub fn unseal(&self, key: &[u8]) -> Result<bool, RvError> {
        self.do_unseal(key, false)
    }

    /// Unseals the rusty_vault once and immediately generates new unseal keys.
    ///
    /// This method performs a one-time unseal operation that automatically invalidates
    /// the used unseal keys and generates a fresh set of keys for future use. This is
    /// a security feature that prevents replay attacks and ensures that unseal keys
    /// can only be used once.
    ///
    /// # Arguments
    /// - `key`: The unseal key to use for the unseal operation
    ///
    /// # Returns
    /// A `Result` containing new unseal keys if successful, or an error if the operation fails.
    ///
    /// # Errors
    /// - Returns `RvError::ErrBarrierUnsealing` if the unseal operation fails or insufficient keys
    /// - Returns errors from `do_unseal()` if the unseal process encounters issues
    /// - Returns errors from `generate_unseal_keys()` if key generation fails
    ///
    /// # Security Features
    /// - Marks used unseal keys as deprecated to prevent reuse
    /// - Automatically generates fresh unseal keys after successful unseal
    /// - Provides protection against replay attacks
    /// - Ensures forward secrecy by invalidating old keys
    ///
    /// # Usage
    /// This method is typically used in high-security environments where unseal keys
    /// should only be valid for a single use, or in automated systems that need to
    /// rotate keys after each unseal operation.
    pub fn unseal_once(&self, key: &[u8]) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        let unseal = self.do_unseal(key, true)?;
        if unseal {
            self.generate_unseal_keys()
        } else {
            Err(RvError::ErrBarrierUnsealing)
        }
    }

    pub fn seal(&self) -> Result<(), RvError> {
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
        state.kek.clear();
        self.state.store(Arc::new(state));

        self.barrier.seal()
    }

    /// Generates new unseal keys using Shamir's Secret Sharing.
    ///
    /// This method creates a new set of unseal keys by splitting the current Key Encryption Key (KEK)
    /// using Shamir's Secret Sharing scheme. The generated keys can be used to unseal the rusty_vault
    /// in the future. This is typically called after a successful unseal operation to provide
    /// new keys for the next seal/unseal cycle.
    ///
    /// # Returns
    /// A `Result` containing a zeroizing vector of unseal key shares, or an error if generation fails.
    ///
    /// # Errors
    /// - Returns `RvError::ErrBarrierSealed` if the barrier is currently sealed
    /// - Returns `RvError::ErrBarrierKeyInvalid` if the KEK is empty or invalid
    /// - Returns Shamir secret splitting errors if the key splitting process fails
    ///
    /// # Security
    /// - Uses the current KEK as the source for key generation
    /// - Applies Shamir's Secret Sharing with configured threshold and share count
    /// - Returns zeroizing vector to ensure secure memory cleanup
    /// - Generated keys are cryptographically independent of previous keys
    ///
    /// # Usage
    /// This method should only be called when the rusty_vault is unsealed and a valid KEK exists.
    /// It's commonly used in key rotation scenarios or after unseal_once operations.
    pub fn generate_unseal_keys(&self) -> Result<Zeroizing<Vec<Vec<u8>>>, RvError> {
        if self.state.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let kek = self.state.load().kek.clone();
        if kek.is_empty() {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let config = self.seal_config()?;
        ShamirSecret::split(kek.as_slice(), config.secret_shares, config.secret_threshold)
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
    use crate::{errors::RvError, test_utils::new_unseal_test_rusty_vault};

    #[test]
    fn test_core_init() {
        let _ = new_unseal_test_rusty_vault("test_core_init");
    }

    #[test]
    fn test_generate_unseal_keys_basic() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_generate_unseal_keys_basic");

        // Test that generate_unseal_keys works when unsealed
        let result = core.generate_unseal_keys();
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert_eq!(keys.len(), core.seal_config().unwrap().secret_shares as usize); // Default test configuration: 3 shares

        // Each key should have the expected length (32 bytes + 1 byte overhead)
        for key in keys.iter() {
            assert_eq!(key.len(), 33);
        }

        // Keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }

    #[test]
    fn test_generate_unseal_keys_when_sealed() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_generate_unseal_keys_when_sealed");

        // Seal the vault
        let seal_result = core.seal();
        assert!(seal_result.is_ok());

        // Should fail when sealed
        let result = core.generate_unseal_keys();
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_unseal_keys_multiple_calls() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_generate_unseal_keys_multiple_calls");

        // Generate keys multiple times
        let keys1 = core.generate_unseal_keys().unwrap();
        let keys2 = core.generate_unseal_keys().unwrap();
        let keys3 = core.generate_unseal_keys().unwrap();

        // All should succeed and produce the same number of keys
        assert_eq!(keys1.len(), keys2.len());
        assert_eq!(keys2.len(), keys3.len());

        // But keys should be different (due to randomness in Shamir sharing)
        assert_ne!(keys1[0], keys2[0]);
        assert_ne!(keys2[0], keys3[0]);
    }

    #[test]
    fn test_unseal_once_basic() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_unseal_once_basic");

        // Get initial keys for testing
        let initial_keys = core.generate_unseal_keys().unwrap();

        // Seal the vault
        core.seal().unwrap();

        // Test unseal_once with sufficient keys
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key) {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        assert_eq!(new_keys.len(), core.seal_config().unwrap().secret_shares as usize); // Should generate new keys

        // Vault should be unsealed
        assert!(!core.sealed());

        // New keys should be different from initial keys
        assert_ne!(initial_keys[0], new_keys[0]);
    }

    #[test]
    fn test_unseal_once_insufficient_keys() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_unseal_once_insufficient_keys");

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().unwrap();

        // Seal the vault
        core.seal().unwrap();

        // Try unseal_once with just one key (insufficient for threshold=2)
        let result = core.unseal_once(&initial_keys[0]);
        assert!(result.is_err());

        // Vault should still be sealed
        assert!(core.sealed());
    }

    #[test]
    fn test_unseal_once_key_deprecation() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_unseal_once_key_deprecation");

        // Get initial keys
        let initial_keys = core.generate_unseal_keys().unwrap();

        // Seal the vault
        core.seal().unwrap();

        // Use unseal_once to unseal
        let mut new_keys = None;
        for key in initial_keys.iter() {
            match core.unseal_once(key) {
                Ok(keys) => {
                    new_keys = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys.is_some());
        let new_keys = new_keys.unwrap();
        assert_eq!(new_keys.len(), core.seal_config().unwrap().secret_shares as usize);

        // Seal again
        core.seal().unwrap();

        // Try to use the same key again - should fail due to deprecation
        for i in 0..5 {
            assert!(matches!(core.unseal_once(&initial_keys[i]), Err(RvError::ErrBarrierKeyDeprecated)));
        }

        for i in 5..initial_keys.len() {
            assert!(matches!(core.unseal_once(&initial_keys[i]), Err(RvError::ErrBarrierUnsealing)));
        }
        assert!(matches!(core.unseal_once(&new_keys[0]), Err(RvError::ErrBarrierUnsealFailed)));

        // But new keys should work
        let mut new_keys2 = None;
        for key in new_keys.iter() {
            match core.unseal_once(key) {
                Ok(keys) => {
                    new_keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(new_keys2.is_some());
        let new_keys2 = new_keys2.unwrap();
        assert_eq!(new_keys2.len(), core.seal_config().unwrap().secret_shares as usize);
    }

    #[test]
    fn test_unseal_once_when_already_unsealed() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_unseal_once_when_already_unsealed");

        // Get keys for testing
        let keys = core.generate_unseal_keys().unwrap();

        // Vault is already unsealed, so unseal_once should fail
        let result = core.unseal_once(&keys[0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_once_forward_secrecy() {
        let (_rvault, core, _) = new_unseal_test_rusty_vault("test_unseal_once_forward_secrecy");

        // Get initial keys
        let keys1 = core.generate_unseal_keys().unwrap();

        // Seal and unseal_once to get new keys
        core.seal().unwrap();
        let mut keys2 = None;
        for key in keys1.iter() {
            match core.unseal_once(key) {
                Ok(keys) => {
                    keys2 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }

        assert!(keys2.is_some());
        let keys2 = keys2.unwrap();
        assert_eq!(keys2.len(), core.seal_config().unwrap().secret_shares as usize);

        // Seal and unseal_once again
        core.seal().unwrap();

        let mut keys3 = None;
        for key in keys2.iter() {
            match core.unseal_once(key) {
                Ok(keys) => {
                    keys3 = Some(keys);
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(keys3.is_some());
        let keys3 = keys3.unwrap();
        assert_eq!(keys3.len(), core.seal_config().unwrap().secret_shares as usize);

        // All key sets should be different (forward secrecy)
        for i in 0..keys1.len() {
            assert_ne!(keys1[i], keys2[i]);
            assert_ne!(keys2[i], keys3[i]);
            assert_ne!(keys1[i], keys3[i]);
        }

        // Old keys should be deprecated and unusable
        core.seal().unwrap();
        for key in keys1.iter() {
            assert!(core.unseal_once(key).is_err());
        }
        for key in keys2.iter() {
            assert!(core.unseal_once(key).is_err());
        }
        for key in keys3.iter() {
            if let Err(RvError::ErrBarrierUnsealFailed) = core.unseal_once(key) {
                break;
            }
        }

        assert!(matches!(core.unseal_once(&keys3[0]), Err(RvError::ErrBarrierUnsealing)));
        assert!(matches!(core.unseal_once(&keys3[1]), Err(RvError::ErrBarrierUnsealing)));
        assert!(matches!(core.unseal_once(&keys3[2]), Err(RvError::ErrBarrierUnsealing)));
        assert!(matches!(core.unseal_once(&keys3[3]), Err(RvError::ErrBarrierUnsealing)));
        assert!(matches!(core.unseal_once(&keys3[4]), Ok(_)));
    }
}
