//! This module provides the 'auth/' path and relevant authentication features.
//!
//! After a successful authentication, a client will be granted a token for further operations.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use lazy_static::lazy_static;

use crate::{
    core::{Core, LogicalBackendNewFunc},
    errors::RvError,
    handler::Handler,
    logical::Backend,
    modules::Module,
    mount::{MountEntry, MountTable},
    router::Router,
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView},
    utils::generate_uuid,
};

pub mod expiration;
pub mod token_store;
pub use expiration::ExpirationManager;
pub use token_store::TokenStore;

const AUTH_CONFIG_PATH: &str = "core/auth";
const AUTH_BARRIER_PREFIX: &str = "auth/";

pub const AUTH_ROUTER_PREFIX: &str = "auth/";

lazy_static! {
    static ref DEFAULT_AUTH_MOUNTS: Vec<MountEntry> = vec![MountEntry {
        tainted: false,
        uuid: generate_uuid(),
        path: "token/".to_string(),
        logical_type: "token".to_string(),
        description: "token based credentials".to_string(),
        options: None,
    }];
}

pub struct AuthRouterStore {
    pub mounts: Arc<MountTable>,
    pub router: Arc<Router>,
}

impl AuthRouterStore {
    pub fn new(mounts: Arc<MountTable>, router: Arc<Router>) -> Self {
        Self { mounts, router }
    }
}

pub struct AuthModule {
    pub name: String,
    pub core: Arc<RwLock<Core>>,
    pub barrier: Arc<dyn SecurityBarrier>,
    pub backends: Mutex<HashMap<String, Arc<LogicalBackendNewFunc>>>,
    pub router_store: RwLock<AuthRouterStore>,
    pub token_store: Arc<TokenStore>,
    pub expiration: Arc<ExpirationManager>,
}

impl AuthModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "auth".to_string(),
            core: Arc::clone(core.self_ref.as_ref().unwrap()),
            barrier: Arc::clone(&core.barrier),
            backends: Mutex::new(HashMap::new()),
            router_store: RwLock::new(AuthRouterStore::new(Arc::new(MountTable::new()), Arc::clone(&core.router))),
            token_store: Arc::new(TokenStore::default()),
            expiration: Arc::new(ExpirationManager::default()),
        }
    }

    pub fn enable_auth(&self, me: &MountEntry) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        {
            let mut auth_table = router_store.mounts.entries.write()?;
            let mut entry = me.clone();

            if !entry.path.ends_with("/") {
                entry.path += "/";
            }

            if entry.path == "/" {
                return Err(RvError::ErrMountPathProtected);
            }

            if entry.logical_type == "token" {
                return Err(RvError::ErrMountFailed);
            }

            for (_, mount_entry) in auth_table.iter() {
                let ent = mount_entry.read()?;
                if ent.path.starts_with(&entry.path) || entry.path.starts_with(&ent.path) {
                    return Err(RvError::ErrMountPathExist);
                }
            }

            let match_mount_path = router_store.router.matching_mount(&entry.path)?;
            if match_mount_path.len() != 0 {
                return Err(RvError::ErrMountPathExist);
            }

            let backend_new_func = self.get_auth_backend(&entry.logical_type)?;
            let backend = backend_new_func(Arc::clone(&self.core))?;

            entry.uuid = generate_uuid();

            let prefix = format!("{}{}/", AUTH_BARRIER_PREFIX, &entry.uuid);
            let view = BarrierView::new(self.barrier.clone(), &prefix);

            let path = format!("{}{}", AUTH_ROUTER_PREFIX, &entry.path);
            let key = entry.path.clone();

            let mount_entry = Arc::new(RwLock::new(entry));

            router_store.router.mount(backend, &path, Arc::clone(&mount_entry), view)?;

            auth_table.insert(key, mount_entry);
        }

        router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())?;

        Ok(())
    }

    pub fn disable_auth(&self, path: &str) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;

        let mut path = path.to_string();
        if !path.ends_with("/") {
            path += "/";
        }

        if path == "token/" {
            return Err(RvError::ErrMountPathProtected);
        }

        let full_path = format!("{}{}", AUTH_ROUTER_PREFIX, &path);
        let view = router_store.router.matching_view(&full_path)?;

        self.taint_auth_entry(&path)?;

        router_store.router.taint(&full_path)?;

        router_store.router.unmount(&full_path)?;

        if view.is_some() {
            view.unwrap().clear()?;
        }

        self.remove_auth_entry(&path)?;

        Ok(())
    }

    pub fn remove_auth_entry(&self, path: &str) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        if router_store.mounts.delete(path) {
            router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())?;
        }
        Ok(())
    }

    pub fn taint_auth_entry(&self, path: &str) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        if router_store.mounts.set_taint(path, true) {
            router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())?;
        }
        Ok(())
    }

    pub fn teardown_auth(&self) -> Result<(), RvError> {
        let mut router_store = self.router_store.write()?;
        router_store.mounts = Arc::new(MountTable::new());
        router_store.router = Arc::new(Router::new());
        Ok(())
    }

    pub fn load_auth(&self) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        if router_store.mounts.load(self.barrier.as_storage(), AUTH_CONFIG_PATH).is_err() {
            router_store.mounts.set_default(DEFAULT_AUTH_MOUNTS.to_vec())?;
            router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())?;
        }

        Ok(())
    }

    pub fn persist_auth(&self) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())
    }

    pub fn setup_auth(&self) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;

        let mounts = router_store.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let barrier_path = format!("{}{}/", AUTH_BARRIER_PREFIX, &entry.uuid);

            let backend_new_func = self.get_auth_backend(&entry.logical_type)?;
            let backend = backend_new_func(Arc::clone(&self.core))?;

            let view = BarrierView::new(Arc::clone(&self.barrier), &barrier_path);
            let path = format!("{}{}", AUTH_ROUTER_PREFIX, &entry.path);

            router_store.router.mount(backend, &path, Arc::clone(mount_entry), view)?;

            if entry.tainted {
                router_store.router.taint(&entry.path)?;
            }
        }

        Ok(())
    }

    pub fn get_auth_backend(&self, logical_type: &str) -> Result<Arc<LogicalBackendNewFunc>, RvError> {
        let backends = self.backends.lock().unwrap();
        if let Some(backend) = backends.get(logical_type) {
            Ok(backend.clone())
        } else {
            Err(RvError::ErrCoreLogicalBackendNoExist)
        }
    }

    pub fn add_auth_backend(&self, logical_type: &str, backend: Arc<LogicalBackendNewFunc>) -> Result<(), RvError> {
        let mut backends = self.backends.lock().unwrap();
        if backends.contains_key(logical_type) {
            return Err(RvError::ErrCoreLogicalBackendExist);
        }
        backends.insert(logical_type.to_string(), backend);
        Ok(())
    }

    pub fn delete_auth_backend(&self, logical_type: &str) -> Result<(), RvError> {
        let mut backends = self.backends.lock().unwrap();
        backends.remove(logical_type);
        Ok(())
    }
}

impl Module for AuthModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let mut router_store = self.router_store.write()?;
        router_store.router = Arc::clone(&core.router);

        Ok(())
    }

    fn init(&mut self, core: &Core) -> Result<(), RvError> {
        let expiration = ExpirationManager::new(core)?;
        self.expiration = Arc::new(expiration);

        let token_store = TokenStore::new(core, Arc::clone(&self.expiration))?;
        self.token_store = Arc::new(token_store);

        self.expiration.set_token_store(Arc::clone(&self.token_store))?;

        let token_store = Arc::clone(&self.token_store);
        let token_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut backend = token_store.new_backend();
            backend.init()?;
            Ok(Arc::new(backend))
        };

        self.add_auth_backend("token", Arc::new(token_backend_new_func))?;
        self.load_auth()?;
        self.setup_auth()?;
        self.expiration.restore()?;

        core.add_handler(Arc::clone(&self.token_store) as Arc<dyn Handler>)?;

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_handler(Arc::clone(&self.token_store) as Arc<dyn Handler>)?;

        self.delete_auth_backend("token")?;
        self.teardown_auth()?;
        Ok(())
    }
}
