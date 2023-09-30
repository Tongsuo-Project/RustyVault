use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::storage::{Storage, StorageEntry};
use crate::storage::barrier_view::BarrierView;
use crate::core::Core;
use crate::router::Router;
use crate::util;
use crate::errors::RvError;

const CORE_MOUNT_CONFIG_PATH: &str = "core/mounts";
const LOGICAL_BARRIER_PREFIX: &str = "logical/";
const SYSTEM_BARRIER_PREFIX: &str  = "sys/";

lazy_static! {
    static ref PROTECTED_MOUNTS: Vec<&'static str> = vec![
        "audit/",
        "auth/",
        "sys/",
    ];
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountEntry {
    pub tainted: bool,
    pub uuid: String,
    pub path: String,
    pub logical_type: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountTable {
    pub entries: Arc<RwLock<HashMap<String, MountEntry>>>,
}

impl MountEntry {
    pub fn new(path: &str, logical_type: &str, desc: &str) -> Self {
        Self {
            tainted: false,
            uuid: String::new(),
            path: path.to_string(),
            logical_type: logical_type.to_string(),
            description: desc.to_string(),
        }
    }
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn hash(&self) -> Result<Vec<u8>, RvError> {
        //let mounts = self.entries.read().unwrap();
        Ok(Vec::new())
    }

    pub fn get(&self, path: &str) -> Result<Option<MountEntry>, RvError> {
        let mounts = self.entries.read().unwrap();
        Ok(mounts.get(path).cloned())
    }

    pub fn delete(&self, path: &str) -> bool {
        let mut mounts = self.entries.write().unwrap();
        mounts.remove(path).is_some()
    }

    pub fn set_taint(&self, path: &str, value: bool) -> bool {
        let mut mounts = self.entries.write().unwrap();
        if let Some(entry) = mounts.get_mut(path) {
            entry.tainted = value;
            return true;
        }
        return false;
    }

    pub fn load(&self, from: &str, storage: &dyn Storage) -> Result<(), RvError> {
        let entry = storage.get(from)?;
        if entry.is_none() {
            return Err(RvError::ErrMountTableNotFound);
        }
        let new_table: MountTable = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        let mut new_entries = new_table.entries.write().unwrap();
        let mut entries = self.entries.write().unwrap();
        entries.clear();
        entries.extend(new_entries.drain());
        Ok(())
    }

    pub fn persist(&self, to: &str, storage: &dyn Storage) -> Result<(), RvError> {
        let value = serde_json::to_string(self)?;
        let entry = StorageEntry {
            key: to.to_string(),
            value: value.into_bytes(),
        };
        storage.put(&entry)?;
        Ok(())
    }
}

impl Core {
    pub fn mount(&self, me: &MountEntry) -> Result<(), RvError> {
        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mounts = self.mounts.as_ref().unwrap();
        let mut table = mounts.entries.write().unwrap();
        let mut entry = me.clone();

        if !entry.path.ends_with("/") {
            entry.path += "/";
        }

        if is_protect_mount(&entry.path) {
            return Err(RvError::ErrMountPathProtected);
        }

        if self.router.matching_mount(&entry.path).len() != 0 {
            return Err(RvError::ErrMountPathExist);
        }

        let backend_new_func = self.get_logical_backend(&me.logical_type)?;
        let backend = backend_new_func(Arc::clone(self.self_ref.as_ref().unwrap()))?;

        entry.uuid = util::generate_uuid();

        let prefix = format!("{}{}/", LOGICAL_BARRIER_PREFIX, &entry.uuid);
        let view = BarrierView::new(self.barrier.clone(), &prefix);

        self.router.mount(Arc::new(backend), &entry.path, &entry.uuid, view)?;

        table.insert(entry.path.clone(), entry);

        mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;

        Ok(())
    }

    pub fn unmount(&self, path: &str) -> Result<(), RvError> {
        let mut path = path.to_string();
        if !path.ends_with("/") {
            path += "/";
        }

        if is_protect_mount(&path) {
            return Err(RvError::ErrMountPathProtected);
        }

        let match_mount = self.router.matching_mount(&path);
        if match_mount.len() == 0 || match_mount != path {
            return Err(RvError::ErrMountNotMatch);
        }

        self.taint_mount_entry(&path)?;

        self.router.unmount(&path)?;

        let view = self.router.matching_view(&path);
        if view.is_some() {
            view.unwrap().clear()?;
        }

        self.remove_mount_entry(&path)?;

        Ok(())
    }

    pub fn remount(&self, dst: &str, src: &str) -> Result<(), RvError> {
        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mut src = src.to_string();
        let mut dst = dst.to_string();

        if !src.ends_with("/") {
            src += "/";
        }

        if !dst.ends_with("/") {
            dst += "/";
        }

        if is_protect_mount(&src) {
            return Err(RvError::ErrMountPathProtected);
        }

        let match_mount = self.router.matching_mount(&src);
        if match_mount.len() == 0 || match_mount != src {
            return Err(RvError::ErrMountNotMatch);
        }

        if self.router.matching_mount(&dst).len() != 0 {
            return Err(RvError::ErrMountPathExist);
        }

        self.taint_mount_entry(&src)?;

        self.router.taint(&src)?;

        let mounts_ref = self.mounts.as_ref().unwrap();
        let mut mounts = mounts_ref.entries.write().unwrap();
        if let Some(entry) = mounts.get_mut(&src) {
            entry.path = dst.clone();
            entry.tainted = false;
        }

        mounts_ref.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;

        self.router.remount(&dst, &src)?;

        self.router.untaint(&dst)?;

        Ok(())
    }

    pub fn setup_mounts(&self) -> Result<(), RvError> {
        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mounts_ref = self.mounts.as_ref().unwrap();
        let mounts = mounts_ref.entries.read().unwrap();

        for entry in mounts.values() {
            let mut barrier_path = format!("{}{}/", LOGICAL_BARRIER_PREFIX, &entry.uuid);
            if entry.logical_type.as_str() == "system" {
                barrier_path = SYSTEM_BARRIER_PREFIX.to_string();
            }

            let backend_new_func = self.get_logical_backend(&entry.logical_type)?;
            let backend = backend_new_func(Arc::clone(self.self_ref.as_ref().unwrap()))?;

            let view = BarrierView::new(self.barrier.clone(), &barrier_path);

            self.router.mount(Arc::new(backend), &entry.path, &entry.uuid, view)?;

            if entry.tainted {
                self.router.taint(&entry.path)?;
            }
        }

        Ok(())
    }

    pub fn unload_mounts(&mut self) -> Result<(), RvError> {
        self.mounts = None;
        self.router = Arc::new(Router::new());
        Ok(())
    }

    fn taint_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mounts = self.mounts.as_ref().unwrap();
        if mounts.set_taint(path, true) {
            mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;
        }
        Ok(())
    }

    fn remove_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mounts = self.mounts.as_ref().unwrap();
        if mounts.delete(path) {
            mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;
        }
        Ok(())
    }
}

fn is_protect_mount(path: &str) -> bool {
    for p in PROTECTED_MOUNTS.iter() {
        if path.starts_with(p) {
            return true;
        }
    }
    return false;
}
