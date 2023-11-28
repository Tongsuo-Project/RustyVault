use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    core::Core,
    errors::RvError,
    router::Router,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::generate_uuid,
};

const CORE_MOUNT_CONFIG_PATH: &str = "core/mounts";
const LOGICAL_BARRIER_PREFIX: &str = "logical/";
const SYSTEM_BARRIER_PREFIX: &str = "sys/";

lazy_static! {
    static ref PROTECTED_MOUNTS: Vec<&'static str> = vec!["audit/", "auth/", "sys/",];
    static ref DEFAULT_CORE_MOUNTS: Vec<MountEntry> = vec![
        MountEntry {
            tainted: false,
            uuid: generate_uuid(),
            path: "secret/".to_string(),
            logical_type: "kv".to_string(),
            description: "key/value secret storage".to_string(),
            options: None,
        },
        MountEntry {
            tainted: false,
            uuid: generate_uuid(),
            path: "sys/".to_string(),
            logical_type: "system".to_string(),
            description: "system endpoints used for control, policy and debugging".to_string(),
            options: None,
        }
    ];
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MountEntry {
    pub tainted: bool,
    pub uuid: String,
    pub path: String,
    pub logical_type: String,
    pub description: String,
    pub options: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountTable {
    pub entries: Arc<RwLock<HashMap<String, Arc<RwLock<MountEntry>>>>>,
}

impl MountEntry {
    pub fn new(path: &str, logical_type: &str, desc: &str) -> Self {
        Self {
            tainted: false,
            uuid: String::new(),
            path: path.to_string(),
            logical_type: logical_type.to_string(),
            description: desc.to_string(),
            options: None,
        }
    }
}

impl MountTable {
    pub fn new() -> Self {
        Self { entries: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn hash(&self) -> Result<Vec<u8>, RvError> {
        //let mounts = self.entries.read()?;
        Ok(Vec::new())
    }

    pub fn get(&self, path: &str) -> Result<Option<Arc<RwLock<MountEntry>>>, RvError> {
        let mounts = self.entries.read()?;
        Ok(mounts.get(path).cloned())
    }

    pub fn delete(&self, path: &str) -> bool {
        match self.entries.write() {
            Ok(mut mounts) => mounts.remove(path).is_some(),
            Err(_) => false,
        }
    }

    pub fn set_taint(&self, path: &str, value: bool) -> bool {
        match self.entries.write() {
            Ok(mounts) => {
                if let Some(mount_entry) = mounts.get(path) {
                    if let Ok(mut entry) = mount_entry.write() {
                        entry.tainted = value;
                        return true;
                    }
                }
            }
            Err(_) => {
                return false;
            }
        }
        return false;
    }

    pub fn set_default(&self, mounts: Vec<MountEntry>) -> Result<(), RvError> {
        let mut table = self.entries.write()?;
        for mount in mounts {
            table.insert(mount.path.clone(), Arc::new(RwLock::new(mount)));
        }
        Ok(())
    }

    pub fn load_or_default(&self, storage: &dyn Storage) -> Result<(), RvError> {
        let entry = storage.get(CORE_MOUNT_CONFIG_PATH)?;
        if entry.is_none() {
            self.set_default(DEFAULT_CORE_MOUNTS.to_vec())?;
            self.persist(CORE_MOUNT_CONFIG_PATH, storage)?;
            return Ok(());
        }

        self.load(storage, CORE_MOUNT_CONFIG_PATH)
    }

    pub fn load(&self, storage: &dyn Storage, path: &str) -> Result<(), RvError> {
        let entry = storage.get(path)?;
        if entry.is_none() {
            return Err(RvError::ErrConfigLoadFailed);
        }

        let new_table: MountTable = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        let mut new_entries = new_table.entries.write()?;
        let mut entries = self.entries.write()?;
        entries.clear();
        entries.extend(new_entries.drain());
        Ok(())
    }

    pub fn persist(&self, to: &str, storage: &dyn Storage) -> Result<(), RvError> {
        let value = serde_json::to_string(self)?;
        let entry = StorageEntry { key: to.to_string(), value: value.into_bytes() };
        storage.put(&entry)?;
        Ok(())
    }
}

impl Core {
    pub fn mount(&self, me: &MountEntry) -> Result<(), RvError> {
        {
            let mut table = self.mounts.entries.write()?;
            let mut entry = me.clone();

            if !entry.path.ends_with("/") {
                entry.path += "/";
            }

            if is_protect_mount(&entry.path) {
                return Err(RvError::ErrMountPathProtected);
            }

            let match_mount_path = self.router.matching_mount(&entry.path)?;
            if match_mount_path.len() != 0 {
                return Err(RvError::ErrMountPathExist);
            }

            let backend_new_func = self.get_logical_backend(&me.logical_type)?;
            let backend = backend_new_func(Arc::clone(self.self_ref.as_ref().unwrap()))?;

            entry.uuid = generate_uuid();

            let prefix = format!("{}{}/", LOGICAL_BARRIER_PREFIX, &entry.uuid);
            let view = BarrierView::new(self.barrier.clone(), &prefix);

            let path = entry.path.clone();

            let mount_entry = Arc::new(RwLock::new(entry));

            self.router.mount(backend, &path, Arc::clone(&mount_entry), view)?;

            table.insert(path, mount_entry);
        }

        self.mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;

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

        let match_mount = self.router.matching_mount(&path)?;
        if match_mount.len() == 0 || match_mount != path {
            return Err(RvError::ErrMountNotMatch);
        }

        let view = self.router.matching_view(&path)?;

        self.taint_mount_entry(&path)?;

        self.router.taint(&path)?;

        self.router.unmount(&path)?;

        if view.is_some() {
            view.unwrap().clear()?;
        }

        self.remove_mount_entry(&path)?;

        Ok(())
    }

    pub fn remount(&self, src: &str, dst: &str) -> Result<(), RvError> {
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

        {
            let mut mounts = self.mounts.entries.write()?;

            let match_mount = self.router.matching_mount(&src)?;
            if match_mount.len() == 0 || match_mount != src {
                return Err(RvError::ErrMountNotMatch);
            }

            let match_mount_dst = self.router.matching_mount(&dst)?;
            if match_mount_dst.len() != 0 {
                return Err(RvError::ErrMountPathExist);
            }

            if let Some(src_mount_entry) = mounts.get(&src) {
                let mut src_entry = src_mount_entry.write()?;
                src_entry.tainted = true;
            }

            self.router.taint(&src)?;

            if let Some(mount_entry) = mounts.remove(&src) {
                let mut entry = mount_entry.write()?;
                entry.path = dst.clone();
                entry.tainted = false;
            }

            self.router.remount(&dst, &src)?;

            self.router.untaint(&dst)?;
        }

        self.mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;

        Ok(())
    }

    pub fn setup_mounts(&mut self) -> Result<(), RvError> {
        let mounts = self.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let mut barrier_path = format!("{}{}/", LOGICAL_BARRIER_PREFIX, &entry.uuid);
            if entry.logical_type.as_str() == "system" {
                barrier_path = SYSTEM_BARRIER_PREFIX.to_string();
            }

            let backend_new_func = self.get_logical_backend(&entry.logical_type)?;
            let backend = backend_new_func(Arc::clone(self.self_ref.as_ref().unwrap()))?;

            let view = BarrierView::new(self.barrier.clone(), &barrier_path);

            self.router.mount(backend, &entry.path, Arc::clone(mount_entry), view)?;

            if entry.logical_type.as_str() == "system" {
                self.system_view = Some(Arc::new(BarrierView::new(self.barrier.clone(), &barrier_path)));
            }

            if entry.tainted {
                self.router.taint(&entry.path)?;
            }
        }

        Ok(())
    }

    pub fn unload_mounts(&mut self) -> Result<(), RvError> {
        let router = Arc::new(Router::new());
        self.router = Arc::clone(&router);
        let mut handlers = self.handlers.write()?;
        handlers[0] = router;
        self.mounts = Arc::new(MountTable::new());
        self.system_view = None;
        Ok(())
    }

    fn taint_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts.set_taint(path, true) {
            self.mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;
        }
        Ok(())
    }

    fn remove_mount_entry(&self, path: &str) -> Result<(), RvError> {
        if self.mounts.delete(path) {
            self.mounts.persist(CORE_MOUNT_CONFIG_PATH, self.barrier.as_storage())?;
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
