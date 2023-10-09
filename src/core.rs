use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use rand::{Rng, thread_rng};
use crate::mount::MountTable;
use crate::router::Router;
use crate::handler::Handler;
use crate::storage::physical::Backend as PhysicalBackend;
use crate::storage::barrier::SecurityBarrier;
use crate::logical::Backend;
use crate::logical::request::Request;
use crate::logical::response::Response;
use crate::module_manager::ModuleManager;
use crate::errors::RvError;

pub type LogicalBackendNewFunc = dyn Fn(Arc<RwLock<Box<Core>>>) -> Result<Box<dyn Backend>, RvError>;

pub struct Core {
    pub self_ref: Option<Arc<RwLock<Box<Core>>>>,
    pub physical: Arc<Box<dyn PhysicalBackend>>,
    pub barrier: Arc<Box<dyn SecurityBarrier>>,
    pub mounts: Option<MountTable>,
    pub router: Arc<Router>,
    pub handlers: Vec<Arc<dyn Handler>>,
    pub logical_backends: Mutex<HashMap<String, Arc<Box<LogicalBackendNewFunc>>>>,
    pub module_manager: ModuleManager,
}

impl Core {
    pub fn inited(&self) -> Result<bool, RvError> {
        self.barrier.inited()
    }

    pub fn init(&mut self) -> Result<(), RvError> {
        let inited = self.inited()?;
        if inited {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotFound);
        }

        let mut key = vec![0u8; 32];
        thread_rng().fill(key.as_mut_slice());
        self.barrier.init(key.as_slice())?;
        // Unseal the barrier
        self.barrier.unseal(key.as_slice())?;
        // Ensure the barrier is re-sealed
        self.module_manager.init(self)?;
        // Perform initial setup
        self.mounts.as_ref().unwrap().load(self.barrier.as_storage())?;
        self.setup_mounts()?;
        // Generate a new root token
        // Prepare to re-seal
        Ok(())
    }

    pub fn get_logical_backend(&self, logical_type: &str) -> Result<Arc<Box<LogicalBackendNewFunc>>, RvError> {
        let logical_backends = self.logical_backends.lock().unwrap();
        if let Some(backend) = logical_backends.get(logical_type) {
            Ok(backend.clone())
        } else {
            Err(RvError::ErrCoreLogicalBackendNoExist)
        }
    }

    pub fn add_logical_backend(&self, logical_type: &str, backend: Arc<Box<LogicalBackendNewFunc>>) -> Result<(), RvError> {
        let mut logical_backends = self.logical_backends.lock().unwrap();
        if logical_backends.contains_key(logical_type) {
            return Err(RvError::ErrCoreLogicalBackendExist);
        }
        logical_backends.insert(logical_type.to_string(), backend);
        Ok(())
    }

    pub fn remove_logical_backend(&self, logical_type: &str) -> Result<(), RvError> {
        let mut logical_backends = self.logical_backends.lock().unwrap();
        logical_backends.remove(logical_type);
        Ok(())
    }

    pub fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = None;

        for handler in &self.handlers {
            let res = handler.pre_route(req)?;
            if res.is_some() {
                return Ok(res);
            }
        }

        for handler in &self.handlers {
            match handler.route(req) {
                Ok(res) => {
                    if res.is_some() {
                        resp = res;
                        break;
                    }
                }
                Err(error) => {
                    if error != RvError::ErrRouterMountNotFound {
                        return Err(error);
                    }
                }
            }
        }

        if resp.is_none() {
            return Err(RvError::ErrCoreRouterNotHandling);
        }

        for handler in &self.handlers {
            handler.post_route(req, resp.as_mut().unwrap())?;
        }

        for handler in &self.handlers {
            handler.log(req, resp.as_ref().unwrap())?;
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

        let mut conf: HashMap<String, String> = HashMap::new();
        conf.insert("path".to_string(), dir.to_string_lossy().into_owned());

        let backend = Arc::new(physical::new_backend("file", &conf).unwrap());
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
        let router = Arc::new(Router::new());
        let mounts = MountTable::new();
        let mut core = Core {
            self_ref: None,
            physical: backend,
            barrier: Arc::new(Box::new(barrier)),
            mounts: Some(mounts),
            router: router.clone(),
            handlers: vec![router],
            logical_backends: Mutex::new(HashMap::new()),
            module_manager: ModuleManager::new(),
        };

        assert!(core.init().is_ok());
    }

    #[test]
    fn test_core_logical_backend() {
        let dir = env::temp_dir().join("rusty_vault_core_logical_backend");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, String> = HashMap::new();
        conf.insert("path".to_string(), dir.to_string_lossy().into_owned());

        let backend = Arc::new(physical::new_backend("file", &conf).unwrap());
        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
        let router = Arc::new(Router::new());
        let mounts = MountTable::new();

        let mut core = Core {
            self_ref: None,
            physical: backend,
            barrier: Arc::new(Box::new(barrier)),
            mounts: Some(mounts),
            router: router.clone(),
            handlers: vec![router],
            logical_backends: Mutex::new(HashMap::new()),
            module_manager: ModuleManager::new(),
        };

        assert!(core.init().is_ok());
    }
}
