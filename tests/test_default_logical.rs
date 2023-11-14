use std::env;
use std::fs;
use std::default::Default;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde_json::{json, Value, Map};
use go_defer::defer;
use rusty_vault::storage::physical;
use rusty_vault::storage::barrier_aes_gcm;
use rusty_vault::core::{Core, SealConfig};
use rusty_vault::logical::{Operation, Request};

fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool, expect: Option<Map<String, Value>>) {
    let mut req = Request::new(path);
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    assert_eq!(resp.is_ok(), is_ok);
    if expect.is_some() {
        let resp = resp.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().data.as_ref().unwrap(), expect.as_ref().unwrap());
    } else {
        if is_ok {
            let resp = resp.unwrap();
            assert!(resp.is_none());
        }
    }
}

fn test_write_api(core: &Core, token: &str, path: &str, is_ok: bool, data: Option<Map<String, Value>>) {
    let mut req = Request::new(path);
    req.operation = Operation::Write;
    req.client_token = token.to_string();
    req.body = data;

    assert_eq!(core.handle_request(&mut req).is_ok(), is_ok);
}

fn test_delete_api(core: &Core, token: &str, path: &str, is_ok: bool) {
    let mut req = Request::new(path);
    req.operation = Operation::Delete;
    req.client_token = token.to_string();
    assert_eq!(core.handle_request(&mut req).is_ok(), is_ok);
}

fn test_list_api(core: &Core, token: &str, path: &str, is_ok: bool, keys_len: usize) {
    let mut req = Request::new(path);
    req.operation = Operation::List;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    assert_eq!(resp.is_ok(), is_ok);
    if is_ok {
        let resp = resp.unwrap();
        assert!(resp.is_some());
        let data = resp.unwrap().data.unwrap();
        let keys = data["keys"].as_array();
        assert_eq!(keys.unwrap().len(), keys_len);
    }
}

fn test_default_secret(core: Arc<RwLock<Core>>, token: &str) {
    let core = core.read().unwrap();

    // create secret
    let kv_data = json!({
        "foo": "bar",
        "zip": "zap",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "secret/goo", true, Some(kv_data.clone()));

    // get secret
    test_read_api(&core, token, "secret/goo", true, Some(kv_data));
    test_read_api(&core, token, "secret/foo", true, None);
    test_read_api(&core, token, "secret1/foo", false, None);

    // list secret
    test_list_api(&core, token, "secret/", true, 1);
}

fn test_kv_logical_backend(core: Arc<RwLock<Core>>, token: &str) {
    let core = core.read().unwrap();

    // mount kv backend to path: kv/
    let mount_data = json!({
        "type": "kv",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/mounts/kv/", true, Some(mount_data));

    let kv_data = json!({
        "foo": "bar",
        "zip": "zap",
    }).as_object().unwrap().clone();

    test_read_api(&core, token, "secret/foo", true, None);

    // create secret
    test_write_api(&core, token, "kv/secret", true, Some(kv_data.clone()));
    test_write_api(&core, token, "kv1/secret", false, Some(kv_data.clone()));

    // get secret
    test_read_api(&core, token, "kv/secret", true, Some(kv_data));
    test_read_api(&core, token, "kv/secret1", true, None);

    // list secret
    test_list_api(&core, token, "kv/", true, 1);

    // update secret
    let kv_data = json!({
        "foo": "bar",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "kv/secret", true, Some(kv_data.clone()));

    // check whether the secret is updated successfully
    test_read_api(&core, token, "kv/secret", true, Some(kv_data));

    // add secret
    let kv_data = json!({
        "foo": "bar",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "kv/foo", true, Some(kv_data.clone()));

    // list secret
    test_list_api(&core, token, "kv/", true, 2);

    // delete secret
    test_delete_api(&core, token, "kv/secret", true);
    test_delete_api(&core, token, "kv/secret11", true);

    // list secret again
    test_list_api(&core, token, "kv/", true, 1);

    // remount kv backend to path: kv/
    let remount_data = json!({
        "from": "kv",
        "to": "vk",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", true, Some(remount_data));

    // get secret from new mount path
    test_read_api(&core, token, "vk/foo", true, Some(kv_data));

    // unmount
    test_delete_api(&core, token, "sys/mounts/vk/", true);

    // Getting the secret should fail
    test_read_api(&core, token, "vk/foo", false, None);
}

fn test_sys_mount_feature(core: Arc<RwLock<Core>>, token: &str) {
    let core = core.read().unwrap();

    // test api: "mounts"
    let mut req = Request::new("sys/mounts");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert!(resp.is_some());
    let data = resp.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap().len(), 2);

    // test api: "mounts/kv" with valid type
    let mount_data = json!({
        "type": "kv",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/mounts/kv/", true, Some(mount_data.clone()));

    // test api: "mounts/kv" with path conflict
    test_write_api(&core, token, "sys/mounts/kv/", false, Some(mount_data));

    // test api: "mounts/nope" with valid type
    let mount_data = json!({
        "type": "nope",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/mounts/nope/", false, Some(mount_data));

    // test api: "remount" with valid path
    let remount_data = json!({
        "from": "kv",
        "to": "vk",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", true, Some(remount_data));

    // test api: "remount" with invalid path
    let remount_data = json!({
        "from": "unknow",
        "to": "vvk",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", false, Some(remount_data));

    // test api: "remount" with dis-path conflict
    let remount_data = json!({
        "from": "vk",
        "to": "secret",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", false, Some(remount_data));

    // test api: "remount" with protect path
    let remount_data = json!({
        "from": "sys",
        "to": "foo",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", false, Some(remount_data));

    // test api: "remount" with default src-path
    let remount_data = json!({
        "from": "secret",
        "to": "bar",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/remount", true, Some(remount_data));
}

fn test_sys_raw_api_feature(core: Arc<RwLock<Core>>, token: &str) {
    let core = core.read().unwrap();

    // test raw read
    let mut req = Request::new("sys/raw/core/mounts");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let data = resp.unwrap().data;
    assert!(data.is_some());
    assert_ne!(data.as_ref().unwrap().len(), 0);
    assert!(data.as_ref().unwrap()["value"].as_str().unwrap().starts_with('{'));

    // test raw write
    let test_data = json!({
        "value": "my test data",
    }).as_object().unwrap().clone();
    test_write_api(&core, token, "sys/raw/test", true, Some(test_data.clone()));

    // test raw read again
    let mut req = Request::new("sys/raw/test");
    req.operation = Operation::Read;
    req.client_token = token.to_string();
    let resp = core.handle_request(&mut req);
    assert!(resp.is_ok());
    let resp = resp.unwrap();
    let data = resp.unwrap().data;
    assert!(data.is_some());
    assert_eq!(data.as_ref().unwrap()["value"].as_str().unwrap(), test_data["value"].as_str().unwrap());

    // test raw delete
    test_delete_api(&core, token, "sys/raw/test", true);

    // test raw read again
    test_read_api(&core, token, "sys/raw/test", true, None);
}

fn test_sys_logical_backend(core: Arc<RwLock<Core>>, token: &str) {
    test_sys_mount_feature(Arc::clone(&core), token);
    test_sys_raw_api_feature(core, token);
}

#[test]
fn test_default_logical() {
    let dir = env::temp_dir().join("rusty_vault_core_init");
    assert!(fs::create_dir(&dir).is_ok());
    defer! (
        assert!(fs::remove_dir_all(&dir).is_ok());
    );

    let mut root_token = String::new();
    println!("root_token: {:?}", root_token);

    let mut conf: HashMap<String, Value> = HashMap::new();
    conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

    let backend = physical::new_backend("file", &conf).unwrap();

    let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

    let c = Arc::new(RwLock::new(Core {
        physical: backend,
        barrier: Arc::new(barrier),
        ..Default::default()
    }));

    {
        let mut core = c.write().unwrap();
        assert!(core.config(Arc::clone(&c), None).is_ok());

        let seal_config = SealConfig {
            secret_shares: 10,
            secret_threshold: 5,
        };

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

        assert!(unsealed);
    }

    {
        println!("root_token: {:?}", root_token);
        test_default_secret(Arc::clone(&c), &root_token);
        test_kv_logical_backend(Arc::clone(&c), &root_token);
        test_sys_logical_backend(Arc::clone(&c), &root_token);
    }
}
