//! This module provides the 'auth/' path and relevant authentication features.
//!
//! After a successful authentication, a client will be granted a token for further operations.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use lazy_static::lazy_static;

use crate::{
    cli::config::MountEntryHMACLevel,
    core::{Core, LogicalBackendNewFunc},
    errors::RvError,
    handler::Handler,
    logical::Backend,
    modules::Module,
    mount::{MountEntry, MountTable},
    router::Router,
    rv_error_response_status,
    storage::{barrier::SecurityBarrier, barrier_view::BarrierView},
    utils::{generate_uuid, is_protect_path},
};

pub mod expiration;
pub mod token_store;
pub use expiration::ExpirationManager;
pub use token_store::TokenStore;

const AUTH_CONFIG_PATH: &str = "core/auth";
const AUTH_BARRIER_PREFIX: &str = "auth/";

pub const AUTH_ROUTER_PREFIX: &str = "auth/";
pub const AUTH_TABLE_TYPE: &str = "auth";

lazy_static! {
    static ref PROTECTED_AUTHS: Vec<&'static str> = vec!["auth/token",];
    static ref DEFAULT_AUTH_MOUNTS: Vec<MountEntry> = vec![MountEntry {
        table: AUTH_TABLE_TYPE.to_string(),
        tainted: false,
        uuid: generate_uuid(),
        path: "token/".to_string(),
        logical_type: "token".to_string(),
        description: "token based credentials".to_string(),
        ..Default::default()
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
    pub token_store: Option<Arc<TokenStore>>,
    pub expiration: Option<Arc<ExpirationManager>>,
}

impl AuthModule {
    pub fn new(core: &Core) -> Result<Self, RvError> {
        Ok(Self {
            name: "auth".to_string(),
            core: Arc::clone(core.self_ref.as_ref().unwrap()),
            barrier: Arc::clone(&core.barrier),
            backends: Mutex::new(HashMap::new()),
            router_store: RwLock::new(AuthRouterStore::new(Arc::new(MountTable::new()), Arc::clone(&core.router))),
            token_store: None,
            expiration: None,
        })
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

            if is_protect_path(&PROTECTED_AUTHS, &[&entry.path]) {
                return Err(RvError::ErrMountPathProtected);
            }

            for (_, mount_entry) in auth_table.iter() {
                let ent = mount_entry.read()?;
                if ent.path.starts_with(&entry.path) || entry.path.starts_with(&ent.path) {
                    return Err(rv_error_response_status!(409, &format!("path is already in use at {}", &entry.path)));
                }
            }

            let match_mount_path = router_store.router.matching_mount(&entry.path)?;
            if match_mount_path.len() != 0 {
                return Err(rv_error_response_status!(409, &format!("path is already in use at {}", match_mount_path)));
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

    pub fn remount_auth(&self, src: &str, dst: &str) -> Result<(), RvError> {
        let mut src = src.to_string();
        let mut dst = dst.to_string();

        if !src.ends_with("/") {
            src += "/";
        }

        if !dst.ends_with("/") {
            dst += "/";
        }

        if !src.starts_with(AUTH_ROUTER_PREFIX) {
            return Err(rv_error_response_status!(400, &format!("cannot remount non-auth mount {}", src)));
        }

        if !dst.starts_with(AUTH_ROUTER_PREFIX) {
            return Err(rv_error_response_status!(
                400,
                &format!("cannot remount auth mount to non-auth mount {}", dst)
            ));
        }

        if is_protect_path(&PROTECTED_AUTHS, &[&src, &dst]) {
            return Err(RvError::ErrMountPathProtected);
        }

        let router_store = self.router_store.read()?;

        let dst_match = router_store.router.matching_mount(&dst)?;
        if dst_match.len() != 0 {
            return Err(RvError::ErrMountPathExist);
        }

        let src_match = router_store.router.matching_mount_entry(&src)?;
        if src_match.is_none() {
            return Err(RvError::ErrMountNotMatch);
        }

        let mut src_entry = src_match.as_ref().unwrap().write()?;
        src_entry.tainted = true;

        router_store.router.taint(&src)?;

        if !(router_store.router.matching_mount(&dst)?).is_empty() {
            return Err(RvError::ErrMountPathExist);
        }

        let src_path = src_entry.path.clone();
        src_entry.path = dst.as_str().trim_start_matches(AUTH_ROUTER_PREFIX).to_string();
        src_entry.tainted = false;

        std::mem::drop(src_entry);

        if let Err(e) = router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage()) {
            let mut src_entry = src_match.as_ref().unwrap().write()?;
            src_entry.path = src_path;
            src_entry.tainted = true;
            return Err(e);
        }

        router_store.router.remount(&dst, &src)?;

        router_store.router.untaint(&dst)?;

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

    pub fn load_auth(&self, hmac_key: Option<&[u8]>, hmac_level: MountEntryHMACLevel) -> Result<(), RvError> {
        let router_store = self.router_store.read()?;
        if router_store.mounts.load(self.barrier.as_storage(), AUTH_CONFIG_PATH, hmac_key, hmac_level).is_err()
        {
            router_store.mounts.set_default(DEFAULT_AUTH_MOUNTS.to_vec(), hmac_key)?;
            router_store.mounts.persist(AUTH_CONFIG_PATH, self.barrier.as_storage())?;
        }

        self.update_auth_mount(hmac_key, hmac_level)
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

    fn update_auth_mount(&self, hmac_key: Option<&[u8]>, hmac_level: MountEntryHMACLevel) -> Result<(), RvError> {
        let mut need_persist = false;
        let router_store = self.router_store.read()?;
        let mounts = router_store.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let mut entry = mount_entry.write()?;
            if entry.table.is_empty() {
                entry.table = AUTH_TABLE_TYPE.to_string();
                need_persist = true;
            }

            if entry.hmac.is_empty() && hmac_key.is_some() && hmac_level == MountEntryHMACLevel::Compat {
                entry.calc_hmac(hmac_key.unwrap())?;
                need_persist = true;
            }
        }

        if need_persist {
            self.persist_auth()?;
        }

        Ok(())
    }
}

impl Module for AuthModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let mut router_store = self.router_store.write()?;
        router_store.router = Arc::clone(&core.router);

        Ok(())
    }

    fn init(&mut self, core: &Core) -> Result<(), RvError> {
        let expiration = ExpirationManager::new(core)?.wrap();
        let token_store = TokenStore::new(core, expiration.clone())?.wrap();

        expiration.set_token_store(&token_store)?;

        self.expiration = Some(expiration.clone());
        self.token_store = Some(token_store.clone());

        let ts = token_store.clone();

        let token_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut backend = token_store.new_backend();
            backend.init()?;
            Ok(Arc::new(backend))
        };

        self.add_auth_backend("token", Arc::new(token_backend_new_func))?;
        self.load_auth(Some(&core.hmac_key), core.mount_entry_hmac_level)?;
        self.setup_auth()?;

        expiration.restore()?;
        expiration.start_check_expired_lease_entries();

        core.add_handler(ts as Arc<dyn Handler>)?;

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_handler(self.token_store.as_ref().unwrap().clone() as Arc<dyn Handler>)?;

        self.delete_auth_backend("token")?;
        self.teardown_auth()?;
        Ok(())
    }
}
