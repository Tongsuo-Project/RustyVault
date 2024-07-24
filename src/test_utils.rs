use std::{
    env, fs,
    collections::HashMap,
    default::Default,
    time::{SystemTime, UNIX_EPOCH},
    sync::{Arc, RwLock},
};

use serde_json::{json, Map, Value};
use lazy_static::lazy_static;

use crate::{
    errors::RvError,
    core::{Core, SealConfig},
    logical::{Operation, Request, Response},
    storage::{self, Backend},
};

lazy_static! {
    pub static ref TEST_DIR: &'static str = "rusty_vault_test";
}

mod tests {
    use super::*;

    #[ctor::ctor]
    fn init() {
        let dir = env::temp_dir().join(*TEST_DIR);
        let _ = fs::remove_dir_all(&dir);
        println!("create rusty_vault_test dir: {}", dir.to_string_lossy().into_owned());
        assert!(fs::create_dir(&dir).is_ok());
    }

    #[ctor::dtor]
    fn cleanup() {
        let dir = env::temp_dir().join(*TEST_DIR);
        let _ = fs::remove_dir_all(&dir);
    }
}

pub fn test_backend(name: &str) -> Arc<dyn Backend> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let test_dir = env::temp_dir().join(format!("{}/{}-{}", *TEST_DIR, name, now).as_str());
    let dir = test_dir.to_string_lossy().into_owned();
    assert!(fs::create_dir(&test_dir).is_ok());

    println!("test backend init, dir: {}", dir);

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".to_string(), Value::String(dir));

    let backend = storage::new_backend("file", &conf);
    assert!(backend.is_ok());

    backend.unwrap()
}

pub fn test_rusty_vault_init(name: &str) -> (String, Arc<RwLock<Core>>) {
    let root_token;
    let backend = test_backend(name);
    let barrier = storage::barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));
    let c = Arc::new(RwLock::new(Core { physical: backend, barrier: Arc::new(barrier), ..Default::default() }));

    {
        let mut core = c.write().unwrap();
        assert!(core.config(Arc::clone(&c), None).is_ok());

        let seal_config = SealConfig { secret_shares: 10, secret_threshold: 5 };

        let result = core.init(&seal_config);
        assert!(result.is_ok());
        let init_result = result.unwrap();
        println!("init_result: {:?}", init_result);

        let mut unsealed = false;
        for i in 0..seal_config.secret_threshold {
            let key = &init_result.secret_shares[i as usize];
            let unseal = core.unseal(key);
            assert!(unseal.is_ok());
            unsealed = unseal.unwrap();
        }

        root_token = init_result.root_token;
        println!("root_token: {:?}", root_token);

        assert!(unsealed);
    }

    (root_token, c)
}

pub fn test_list_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    println!("list resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    println!("read resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_write_api(
    core: &Core,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = data;

    let resp = core.handle_request(&mut req);
    println!("write resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_delete_api(
    core: &Core,
    token: &str,
    path: &str,
    is_ok: bool,
    data: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    req.body = data;
    let resp = core.handle_request(&mut req);
    println!("delete resp: {:?}", resp);
    assert_eq!(resp.is_ok(), is_ok);
    resp
}

pub fn test_mount_api(core: &Core, token: &str, mtype: &str, path: &str) {
    let data = json!({
        "type": mtype,
    })
    .as_object()
    .unwrap()
    .clone();

    let resp = test_write_api(core, token, format!("sys/mounts/{}", path).as_str(), true, Some(data));
    assert!(resp.is_ok());
}

pub fn test_mount_auth_api(core: &Core, token: &str, atype: &str, path: &str) {
    let auth_data = json!({
        "type": atype,
    })
    .as_object()
    .unwrap()
    .clone();

    let resp = test_write_api(core, token, format!("sys/auth/{}", path).as_str(), true, Some(auth_data));
    assert!(resp.is_ok());
}

