use std::sync::{Mutex, Arc};
use radix_trie::{Trie, TrieCommon};
use crate::logical::Backend;
use crate::logical::request::Request;
use crate::logical::response::Response;
use crate::handler::Handler;
use crate::storage::barrier_view::BarrierView;
use crate::errors::RvError;

struct MountEntry {
    tainted: bool,
    salt: String,
    backend: Arc<Box<dyn Backend>>,
    view: Arc<BarrierView>,
    root_paths: Trie<String, bool>,
    login_paths: Trie<String, bool>,
}

pub struct Router {
    root: Arc<Mutex<Trie<String, MountEntry>>>,
}

impl MountEntry {
    fn salt_id(&self, id: &str) -> String {
        return id.to_string();
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            root: Arc::new(Mutex::new(Trie::new())),
        }
    }

    pub fn mount(&self, backend: Arc<Box<dyn Backend>>, prefix: &str, salt: &str, view: BarrierView) -> Result<(), RvError> {
        let mut root = self.root.lock().unwrap();

        // Check if this is a nested mount
        if let Some(_existing) = root.get_ancestor(prefix) {
            return Err(RvError::ErrRouterMountConflict);
        }

        let login_paths = backend.get_login_paths().unwrap_or(Arc::new(Vec::new()));
        let root_paths = backend.get_root_paths().unwrap_or(Arc::new(Vec::new()));

        let me = MountEntry {
            tainted: false,
            backend,
            salt: salt.to_string(),
            view: Arc::new(view),
            root_paths: new_radix_from_paths(root_paths.as_ref()),
            login_paths: new_radix_from_paths(login_paths.as_ref()),
        };

        root.insert(prefix.to_string(), me);
        Ok(())
    }

    pub fn unmount(&self, prefix: &str) -> Result<(), RvError> {
        let mut root = self.root.lock().unwrap();
        root.remove(prefix);
        Ok(())
    }

    pub fn remount(&self, dst: &str, src: &str) -> Result<(), RvError> {
        let mut root = self.root.lock().unwrap();
        if let Some(raw) = root.remove(src) {
            root.insert(dst.to_string(), raw);
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn taint(&self, path: &str) -> Result<(), RvError> {
        let mut root = self.root.lock().unwrap();
        if let Some(raw) = root.get_mut(path) {
            raw.tainted = true;
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn untaint(&self, path: &str) -> Result<(), RvError> {
        let mut root = self.root.lock().unwrap();
        if let Some(raw) = root.get_mut(path) {
            raw.tainted = false;
            Ok(())
        } else {
            Err(RvError::ErrRouterMountNotFound)
        }
    }

    pub fn matching_mount(&self, path: &str) -> String {
        let root = self.root.lock().unwrap();
        if let Some(entry) = root.get_ancestor(path) {
            entry.key().unwrap().clone()
        } else {
            "".to_string()
        }
    }

    pub fn matching_view(&self, path: &str) -> Option<Arc<BarrierView>> {
        let root = self.root.lock().unwrap();
        if let Some(entry) = root.get_ancestor(path) {
            let me = entry.value().unwrap();
            Some(me.view.clone())
        } else {
            None
        }
    }

    pub fn is_login_path(&self, path: &str) -> bool {
        let root = self.root.lock().unwrap();

        let entry = root.get_ancestor(path);
        if entry.is_none() {
            return false;
        }

        let entry = entry.as_ref().unwrap();
        let mount = entry.key().unwrap().as_str();
        let me = entry.value().unwrap();
        let remain = path.replacen(mount, "", 1);

        let login_entry = me.login_paths.get_ancestor(remain.as_str());
        if login_entry.is_none() {
            return false;
        }

        let login_path_match = login_entry.as_ref().unwrap().key().unwrap();
        if *login_entry.as_ref().unwrap().value().unwrap() {
            return remain.starts_with(login_path_match );
        }

        return remain == *login_path_match
    }

    pub fn is_root_path(&self, path: &str) -> bool {
        let root = self.root.lock().unwrap();

        let entry = root.get_ancestor(path);
        if entry.is_none() {
            return false;
        }

        let entry = entry.as_ref().unwrap();
        let mount = entry.key().unwrap().as_str();
        let me = entry.value().unwrap();
        let remain = path.replacen(mount, "", 1);

        let root_entry = me.root_paths.get_ancestor(remain.as_str());
        if root_entry.is_none() {
            return false;
        }

        let root_path_match = root_entry.as_ref().unwrap().key().unwrap();
        if *root_entry.as_ref().unwrap().value().unwrap() {
            return remain.starts_with(root_path_match );
        }

        return remain == *root_path_match
    }
}

impl Handler for Router {
    fn route(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if !req.path.contains('/') {
            req.path.push('/');
        }

        let root = self.root.lock().unwrap();

        let entry = root.get_ancestor(req.path.as_str());
        if entry.is_none() {
            return Err(RvError::ErrRouterMountNotFound);
        }

        let entry = entry.as_ref().unwrap();
        let mount = entry.key().unwrap().as_str();
        let me = entry.value().unwrap();
        if me.tainted {
/*
            match req.operation {
                Operation::Revoke | Operation::Rollback => (),
                _ => return Err(format!("no handler for route '{}'", req.path)),
            }
*/
        }

        let mut original_conn = None;
        if !self.is_login_path(req.path.as_str()) {
            original_conn = req.connection.take();
        }

        let original = req.path.clone();
        req.path = req.path.replacen(mount, "", 1);
        if req.path == "/" {
            req.path = String::new();
        }

        //req.storage = Some(Arc::new(Box::new(me.view.as_storage())));
        req.storage = Some(me.view.clone());

        if !req.path.starts_with("auth/token/") {
            req.client_token = me.salt_id(&req.client_token);
        }

        let response = me.backend.handle_request(req)?;

        req.path = original;
        req.connection = original_conn;
        req.storage = None;
        req.client_token = req.client_token.clone();

        Ok(Some(response.unwrap()))
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
