use std::sync::{Arc, RwLock};
use radix_trie::{Trie, TrieCommon};
use crate::logical::{Operation, Backend, Request, Response};
use crate::handler::Handler;
use crate::storage::barrier_view::BarrierView;
use crate::errors::RvError;

struct MountEntry {
    tainted: bool,
    salt: String,
    backend: Arc<dyn Backend>,
    view: Arc<BarrierView>,
    root_paths: Trie<String, bool>,
    unauth_paths: Trie<String, bool>,
}

pub struct Router {
    root: Arc<RwLock<Trie<String, MountEntry>>>,
}

impl MountEntry {
    fn salt_id(&self, id: &str) -> String {
        return id.to_string();
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            root: Arc::new(RwLock::new(Trie::new())),
        }
    }

    pub fn mount(&self, backend: Arc<dyn Backend>, prefix: &str, salt: &str, view: BarrierView) -> Result<(), RvError> {
        let mut root = self.root.write()?;

        // Check if this is a nested mount
        if let Some(_existing) = root.get_ancestor(prefix) {
            return Err(RvError::ErrRouterMountConflict);
        }

        let unauth_paths = backend.get_unauth_paths().unwrap_or(Arc::new(Vec::new()));
        let root_paths = backend.get_root_paths().unwrap_or(Arc::new(Vec::new()));

        let me = MountEntry {
            tainted: false,
            backend,
            salt: salt.to_string(),
            view: Arc::new(view),
            root_paths: new_radix_from_paths(root_paths.as_ref()),
            unauth_paths: new_radix_from_paths(unauth_paths.as_ref()),
        };

        root.insert(prefix.to_string(), me);
        Ok(())
    }

    pub fn unmount(&self, prefix: &str) -> Result<(), RvError> {
        let mut root = self.root.write()?;
        root.remove(prefix);
        Ok(())
    }

    pub fn remount(&self, dst: &str, src: &str) -> Result<(), RvError> {
        let mut root = self.root.write()?;
        if let Some(raw) = root.remove(src) {
            root.insert(dst.to_string(), raw);
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn taint(&self, path: &str) -> Result<(), RvError> {
        let mut root = self.root.write()?;
        if let Some(raw) = root.get_mut(path) {
            raw.tainted = true;
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn untaint(&self, path: &str) -> Result<(), RvError> {
        let mut root = self.root.write()?;
        if let Some(raw) = root.get_mut(path) {
            raw.tainted = false;
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn matching_mount(&self, path: &str) -> Result<String, RvError> {
        let root = self.root.read()?;
        if let Some(entry) = root.get_ancestor(path) {
            Ok(entry.key().unwrap().clone())
        } else {
            Ok("".to_string())
        }
    }

    pub fn matching_view(&self, path: &str) -> Result<Option<Arc<BarrierView>>, RvError> {
        let root = self.root.read()?;
        if let Some(entry) = root.get_ancestor(path) {
            let me = entry.value().unwrap();
            Ok(Some(me.view.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn is_unauth_path(&self, path: &str) -> Result<bool, RvError> {
        let root = self.root.read()?;

        let entry = root.get_ancestor(path);
        if entry.is_none() {
            return Ok(false);
        }

        let entry = entry.as_ref().unwrap();
        let mount = entry.key().unwrap().as_str();
        let me = entry.value().unwrap();
        let remain = path.replacen(mount, "", 1);

        let unauth_entry = me.unauth_paths.get_ancestor(remain.as_str());
        if unauth_entry.is_none() {
            return Ok(false);
        }

        let unauth_path_match = unauth_entry.as_ref().unwrap().key().unwrap();
        if *unauth_entry.as_ref().unwrap().value().unwrap() {
            return Ok(remain.starts_with(unauth_path_match));
        }

        return Ok(remain == *unauth_path_match);
    }

    pub fn is_root_path(&self, path: &str) -> Result<bool, RvError> {
        let root = self.root.read()?;

        let entry = root.get_ancestor(path);
        if entry.is_none() {
            return Ok(false);
        }

        let entry = entry.as_ref().unwrap();
        let mount = entry.key().unwrap().as_str();
        let me = entry.value().unwrap();
        let remain = path.replacen(mount, "", 1);

        let root_entry = me.root_paths.get_ancestor(remain.as_str());
        if root_entry.is_none() {
            return Ok(false);
        }

        let root_path_match = root_entry.as_ref().unwrap().key().unwrap();
        if *root_entry.as_ref().unwrap().value().unwrap() {
            return Ok(remain.starts_with(root_path_match ));
        }

        return Ok(remain == *root_path_match);
    }

    pub fn as_handler(&self) -> &dyn Handler {
        self
    }
}

impl Handler for Router {
    fn name(&self) -> String {
        "core_router".to_string()
    }

    fn route(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if !req.path.contains('/') {
            req.path.push('/');
        }

        let original = req.path.clone();
        let mut original_conn = None;
        let is_unauth_path = self.is_unauth_path(req.path.as_str())?;
        if !is_unauth_path {
            original_conn = req.connection.take();
        }
        let client_token = req.client_token.clone();

        let backend = {
            let root = self.root.read()?;
            let entry = root.get_ancestor(req.path.as_str());
            if entry.is_none() {
                return Err(RvError::ErrRouterMountNotFound);
            }

            let entry = entry.as_ref().unwrap();
            let mount = entry.key().unwrap().as_str();
            let me = entry.value().unwrap();
            if me.tainted {
                match req.operation {
                    Operation::Revoke | Operation::Rollback => (),
                    _ => return Err(RvError::ErrRouterMountNotFound),
                }
            }

            req.path = req.path.replacen(&mount, "", 1);
            if req.path == "/" {
                req.path = String::new();
            }

            req.storage = Some(me.view.clone());

            if !req.path.starts_with("auth/token/") {
                req.client_token = me.salt_id(&req.client_token);
            }

            me.backend.clone()
        };

        let response = backend.handle_request(req)?;

        req.path = original;
        req.connection = original_conn;
        req.storage = None;
        req.client_token = client_token;

        Ok(response)
    }
}

fn new_radix_from_paths(paths: &[String]) -> Trie<String, bool> {
    let mut radix_paths = Trie::new();
    for path in paths {
        // Check if this is a prefix or exact match
        let prefix_match = path.ends_with('*');
        let path = if prefix_match {
            &path[..path.len() - 1]
        } else {
            path
        };

        radix_paths.insert(path.to_string(), prefix_match);
    }
    radix_paths
}
