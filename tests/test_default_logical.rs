use std::env;
use std::fs;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use serde_json::{json};
use go_defer::defer;
use rusty_vault::storage::physical;
use rusty_vault::storage::barrier_aes_gcm;
use rusty_vault::core::Core;
use rusty_vault::router::Router;
use rusty_vault::mount::MountTable;
use rusty_vault::module_manager::ModuleManager;
use rusty_vault::logical::{Operation, Request};

fn test_default_secret(core: Arc<RwLock<Box<Core>>>) {
    let core = core.read().unwrap();

    let kv_data = json!({
        "foo": "bar",
        "zip": "zap",
    }).as_object().unwrap().clone();
    let mut req = Request::new("secret/goo");
    req.operation = Operation::Write;
    req.body = Some(kv_data.clone());

    assert!(core.handle_request(&mut req).is_ok());

    req = Request::new("secret/goo");
    req.operation = Operation::Read;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.unwrap().body.unwrap(), kv_data);

    req = Request::new("secret/");
    req.operation = Operation::List;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
}

fn test_mount_kv(core: Arc<RwLock<Box<Core>>>) {
    let core = core.read().unwrap();
    let mut req = Request::new("sys/mounts/kv/");
    req.operation = Operation::Write;
    req.body = Some(json!({
        "type": "kv",
    }).as_object().unwrap().clone());

    assert!(core.handle_request(&mut req).is_ok());

    let kv_data = json!({
        "foo": "bar",
        "zip": "zap",
    }).as_object().unwrap().clone();
    req = Request::new("kv/secret");
    req.operation = Operation::Write;
    req.body = Some(kv_data.clone());

    assert!(core.handle_request(&mut req).is_ok());

    req = Request::new("kv/secret");
    req.operation = Operation::Read;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.unwrap().body.unwrap(), kv_data);

    req = Request::new("kv/");
    req.operation = Operation::List;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let body = resp.unwrap().body.unwrap();
    let keys = body["keys"].as_array();
    assert_eq!(keys.unwrap().len(), 1);

    let kv_data = json!({
        "foo": "bar",
    }).as_object().unwrap().clone();
    req = Request::new("kv/foo");
    req.operation = Operation::Write;
    req.body = Some(kv_data.clone());

    assert!(core.handle_request(&mut req).is_ok());

    req = Request::new("kv/");
    req.operation = Operation::List;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let body = resp.unwrap().body.unwrap();
    let keys = body["keys"].as_array();
    assert_eq!(keys.unwrap().len(), 2);

    req = Request::new("kv/secret");
    req.operation = Operation::Delete;
    req.body = None;
    assert!(core.handle_request(&mut req).is_ok());

    req = Request::new("kv/");
    req.operation = Operation::List;
    req.body = None;
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let body = resp.unwrap().body.unwrap();
    let keys = body["keys"].as_array();
    assert_eq!(keys.unwrap().len(), 1);
}

#[test]
fn test_default_logical() {
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

    let c = Arc::new(RwLock::new(Box::new(Core {
        self_ref: None,
        physical: backend,
        barrier: Arc::new(Box::new(barrier)),
        mounts: Some(mounts),
        router: router.clone(),
        handlers: vec![router],
        logical_backends: Mutex::new(HashMap::new()),
        module_manager: ModuleManager::new(),
    })));

    {
        let mut core = c.write().unwrap();
        core.self_ref = Some(Arc::clone(&c));

        assert!(core.init().is_ok());
    }

    {
        test_default_secret(Arc::clone(&c));
        test_mount_kv(Arc::clone(&c));
    }
}
