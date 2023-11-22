use std::{
    sync::{Arc, Mutex, RwLock},
    collections::HashMap,
};
use as_any::{Downcast};
use serde::{Serialize, Deserialize};
use go_defer::defer;
use crate::{
    cli::config::Config,
    shamir::{ShamirSecret, SHAMIR_OVERHEAD},
    mount::MountTable,
    router::Router,
    handler::Handler,
    logical::{
        Backend,
        Request,
        Response,
    },
    storage::{
        physical,
        physical::{
            Backend as PhysicalBackend,
            BackendEntry as PhysicalBackendEntry},
        barrier::SecurityBarrier,
        barrier_view::BarrierView,
        barrier_aes_gcm,
    },
    module_manager::ModuleManager,
    modules::{
        auth::AuthModule,
        pki::PkiModule,
    },
    errors::RvError,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitResult {
    pub secret_shares: Vec<Vec<u8>>,
    pub root_token: String,
}

pub struct Core {
    pub self_ref: Option<Arc<RwLock<Core>>>,
    pub physical: Arc<dyn PhysicalBackend>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub system_view: Option<Arc<BarrierView>>,
    pub mounts: Arc<MountTable>,
    pub router: Arc<Router>,
    pub handlers: RwLock<Vec<Arc<dyn Handler>>>,
    pub logical_backends: Mutex<HashMap<String, Arc<LogicalBackendNewFunc>>>,
    pub module_manager: ModuleManager,
    pub sealed: bool,
    pub unseal_key_shares: Vec<Vec<u8>>,
}

impl Default for Core {
    fn default() -> Self {
        let backend: Arc<dyn PhysicalBackend> = Arc::new(physical::mock::MockBackend::new());
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
        let router = Arc::new(Router::new());

        Core {
            self_ref: None,
            physical: backend,
            barrier: Arc::new(barrier),
            system_view: None,
            mounts: Arc::new(MountTable::new()),
            router: Arc::clone(&router),
            handlers: RwLock::new(vec![router]),
            logical_backends: Mutex::new(HashMap::new()),
            module_manager: ModuleManager::new(),
            sealed: true,
            unseal_key_shares: Vec::new(),
        }
    }
}


impl Core {
    pub fn config(&mut self, core: Arc<RwLock<Core>>, _config: Option<Config>) -> Result<(), RvError> {
        self.module_manager.set_default_modules(Arc::clone(&core))?;
        self.self_ref = Some(Arc::clone(&core));

        // add auth_module
        let auth_module = AuthModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(auth_module))))?;

        // add pki_module
        let pki_module = PkiModule::new(self);
        self.module_manager.add_module(Arc::new(RwLock::new(Box::new(pki_module))))?;

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

        let _ = seal_config.validate()?;

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
        let master_key = barrier.generate_key()?;

        // Initialize the barrier
        barrier.init(master_key.as_slice())?;

        let mut init_result = InitResult {
            secret_shares: Vec::new(),
            root_token: String::new(),
        };

        if seal_config.secret_shares == 1 {
            init_result.secret_shares.push(master_key.clone());
        } else {
            init_result.secret_shares = ShamirSecret::split(&master_key,
                                                      seal_config.secret_shares,
                                                      seal_config.secret_threshold)?;
        }

        log::debug!("master_key: {}", hex::encode(&master_key));
        log::debug!("seal config: {:?}", seal_config);
        log::debug!("secret_shares:");
        for key in init_result.secret_shares.iter() {
            log::debug!("{}", hex::encode(&key));
        }

        // Unseal the barrier
        barrier.unseal(master_key.as_slice())?;

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
                let te = auth_module.token_store.root_token()?;
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

    pub fn get_logical_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        let logical_backends = self.logical_backends.lock().unwrap();
        if let Some(backend) = logical_backends.get(logical_type) {
            Ok(backend.clone())
        } else {
            Err(RvError::ErrCoreLogicalBackendNoExist)
        }
    }

    pub fn add_logical_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        let mut logical_backends = self.logical_backends.lock().unwrap();
        if logical_backends.contains_key(logical_type) {
            return Err(RvError::ErrCoreLogicalBackendExist);
        }
        logical_backends.insert(logical_type.to_string(), backend);
        Ok(())
    }

    pub fn delete_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        let mut logical_backends = self.logical_backends.lock().unwrap();
        logical_backends.remove(logical_type);
        Ok(())
    }

    pub fn add_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RvError> {
        let mut handlers = self.handlers.write()?;
        if let Some(_) = handlers.iter().find(|h| h.name() == handler.name()) {
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

    pub fn seal_config(&self) -> Result<SealConfig, RvError> {
        let pe = self.physical.get(SEAL_CONFIG_PATH)?;

        if pe.is_none() {
            return Err(RvError::ErrCoreSealConfigNotFound);
        }

        let config: SealConfig = serde_json::from_slice(pe.unwrap().value.as_slice())?;
        let _ = config.validate()?;
        Ok(config)
    }

    pub fn sealed(&self) -> bool {
        return self.sealed;
    }

    pub fn unseal_progress(&self) -> usize {
        return self.unseal_key_shares.len();
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
        if self.unseal_key_shares.iter().find(|&v| *v == key).is_some() {
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
        } else {
            if let Some(res) = ShamirSecret::combine(self.unseal_key_shares.clone()) {
                master_key = res;
                self.unseal_key_shares.clear();
            } else {
                //TODO
                self.unseal_key_shares.clear();
                return Err(RvError::ErrBarrierKeyInvalid);
            }
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
        self.mounts.load_or_default(self.barrier.as_storage())?;

        self.setup_mounts()?;

        self.module_manager.init(self)?;

        Ok(())
    }

    fn pre_seal(&mut self) -> Result<(), RvError> {
        self.module_manager.cleanup(self)?;
        self.unload_mounts()?;
        Ok(())
    }

    pub fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = None;
        let mut err: Option<RvError> = None;
        let handlers = self.handlers.read()?;

        if self.sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        for handler in handlers.iter() {
            match handler.pre_route(req) {
                Ok(res) => {
                    if res.is_some() {
                        resp = res;
                        break;
                    }
                }
                Err(error) => {
                    if error != RvError::ErrHandlerDefault {
                        err = Some(error);
                        break;
                    }
                }
            }
        }

        if resp.is_none() && err.is_none() {
            for handler in handlers.iter() {
                match handler.route(req) {
                    Ok(res) => {
                        if res.is_some() {
                            resp = res;
                            break;
                        }
                    }
                    Err(error) => {
                        if error != RvError::ErrHandlerDefault {
                            err = Some(error);
                            break;
                        }
                    }
                }
            }

            if err.is_none() {
                for handler in handlers.iter() {
                    match handler.post_route(req, &mut resp) {
                        Ok(_) => {
                        }
                        Err(error) => {
                            if error != RvError::ErrHandlerDefault {
                                err = Some(error);
                                break;
                            }
                        }
                    }
                }
            }
        }

        for handler in handlers.iter() {
            match handler.log(req, &resp) {
                Ok(_) => {
                }
                Err(error) => {
                    if error != RvError::ErrHandlerDefault {
                        err = Some(error);
                        break;
                    }
                }
            }
        }

        if err.is_some() {
            return Err(err.unwrap());
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::sync::Arc;
    use std::collections::HashMap;
    use serde_json::Value;
    use go_defer::defer;
    use crate::storage::physical;
    use crate::storage::barrier_aes_gcm;
    use super::*;

    #[test]
    fn test_core_init() {
        let dir = env::temp_dir().join("rusty_vault_core_init");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
        let router = Arc::new(Router::new());
        let mounts = MountTable::new();
        let core = Arc::new(RwLock::new(Core {
            self_ref: None,
            physical: backend,
            barrier: Arc::new(barrier),
            system_view: None,
            mounts: Arc::new(mounts),
            router: router.clone(),
            handlers: RwLock::new(vec![router]),
            logical_backends: Mutex::new(HashMap::new()),
            module_manager: ModuleManager::new(),
            sealed: true,
            unseal_key_shares: Vec::new(),
        }));

        {
            let mut c = core.write().unwrap();
            assert!(c.config(Arc::clone(&core), None).is_ok());

            let seal_config = SealConfig {
                secret_shares: 10,
                secret_threshold: 5,
            };

            let result = c.init(&seal_config);
            assert!(result.is_ok());
            let init_result = result.unwrap();

            let mut unsealed = false;
            for i in 0..seal_config.secret_threshold {
                let key = &init_result.secret_shares[i as usize];
                let unseal = c.unseal(key);
                assert!(unseal.is_ok());
                unsealed = unseal.unwrap();
            }

            assert!(unsealed);
        }
    }

    #[test]
    fn test_core_logical_backend() {
        let dir = env::temp_dir().join("rusty_vault_core_logical_backend");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

        let core = Arc::new(RwLock::new(Core {
            physical: backend,
            barrier: Arc::new(barrier),
            ..Default::default()
        }));

        {
            let mut c = core.write().unwrap();
            assert!(c.config(Arc::clone(&core), None).is_ok());

            let seal_config = SealConfig {
                secret_shares: 10,
                secret_threshold: 5,
            };

            let result = c.init(&seal_config);
            assert!(result.is_ok());
            let init_result = result.unwrap();

            let mut unsealed = false;
            for i in 0..seal_config.secret_threshold {
                let key = &init_result.secret_shares[i as usize];
                let unseal = c.unseal(key);
                assert!(unseal.is_ok());
                unsealed = unseal.unwrap();
            }

            assert!(unsealed);
        }
    }
}
