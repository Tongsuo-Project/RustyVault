use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use better_default::Default;
use serde_json::{Map, Value};

use super::Module;
use crate::{
    core::Core,
    errors::RvError,
    handler::AuthHandler,
    logical::{Backend, Request, Response},
};

pub mod policy;
pub use policy::{Permissions, Policy, PolicyPathRules, PolicyType};

pub mod policy_store;
pub use policy_store::PolicyStore;

pub mod acl;

#[derive(Default)]
pub struct PolicyModule {
    #[default("policy".into())]
    pub name: String,
    pub core: Arc<RwLock<Core>>,
    pub policy_store: Arc<PolicyStore>,
}

impl PolicyModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "policy".into(),
            core: Arc::clone(core.self_ref.as_ref().unwrap()),
            policy_store: Arc::new(PolicyStore::default()),
        }
    }

    pub fn setup_policy(&mut self) -> Result<(), RvError> {
        self.policy_store.load_default_acl_policy()
    }

    pub fn handle_policy_list(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut policies = self.policy_store.list_policy(PolicyType::Acl)?;

        // TODO: After the "namespace" feature is added here, it is necessary to determine whether it is the root
        // namespace before the root can be added.
        policies.push("root".into());

        let mut resp = Response::list_response(&policies);

        if req.path.starts_with("policy") {
            let data = resp.data.as_mut().unwrap();
            data.insert("policies".into(), data["keys"].clone());
        }
        Ok(Some(resp))
    }

    pub fn handle_policy_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        if let Some(policy) = self.policy_store.get_policy(&name, PolicyType::Acl)? {
            let mut resp_data = Map::new();
            resp_data.insert("name".into(), Value::String(name));

            // If the request is from sys/policy/ we handle backwards compatibility
            if req.path.starts_with("policy") {
                resp_data.insert("rules".into(), Value::String(policy.raw.clone()));
            } else {
                resp_data.insert("policy".into(), Value::String(policy.raw.clone()));
            }

            let resp = Response::data_response(Some(resp_data));
            if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
                policy.add_sentinel_policy_data(&resp)?;
            }

            return Ok(Some(resp));
        }
        Ok(None)
    }

    pub fn handle_policy_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let policy_str = req.get_data_as_str("policy")?;
        let policy_raw = if let Ok(policy_bytes) = STANDARD.decode(&policy_str) {
            String::from_utf8_lossy(&policy_bytes).to_string()
        } else {
            policy_str
        };

        let mut policy = Policy::from_str(&policy_raw)?;
        policy.name = name;

        if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
            policy.input_sentinel_policy_data(req)?;
        }

        self.policy_store.set_policy(policy)?;

        Ok(None)
    }

    pub fn handle_policy_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        self.policy_store.delete_policy(&name, PolicyType::Acl)?;
        Ok(None)
    }
}

impl Module for PolicyModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn init(&mut self, core: &Core) -> Result<(), RvError> {
        self.policy_store = PolicyStore::new(core)?;

        self.setup_policy()?;

        core.add_auth_handler(Arc::clone(&self.policy_store) as Arc<dyn AuthHandler>)?;

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_auth_handler(Arc::clone(&self.policy_store) as Arc<dyn AuthHandler>)?;
        self.policy_store = Arc::new(PolicyStore::default());
        Ok(())
    }
}

#[cfg(test)]
mod mod_policy_tests {
    use serde_json::json;

    use super::*;
    use crate::{
        logical::{Operation, Request},
        test_utils::{
            test_delete_api, test_list_api, test_mount_api, test_mount_auth_api, test_read_api, test_rusty_vault_init,
            test_write_api,
        },
    };

    async fn test_write_policy(core: &Core, token: &str, name: &str, policy: &str) {
        let data = json!({
            "policy": policy,
        })
        .as_object()
        .unwrap()
        .clone();

        let resp = test_write_api(core, token, format!("sys/policy/{}", name).as_str(), true, Some(data)).await;
        assert!(resp.is_ok());
    }

    async fn test_read_policy(core: &Core, token: &str, name: &str) -> Result<Option<Response>, RvError> {
        let resp = test_read_api(core, token, format!("sys/policy/{}", name).as_str(), true).await;
        assert!(resp.is_ok());
        resp
    }

    async fn test_delete_policy(core: &Core, token: &str, name: &str) {
        assert!(test_delete_api(core, token, format!("sys/policy/{}", name).as_str(), true, None).await.is_ok());
    }

    async fn test_write_user(
        core: &Core,
        token: &str,
        path: &str,
        username: &str,
        password: &str,
        policy: &str,
        ttl: i32,
    ) {
        let user_data = json!({
            "password": password,
            "token_policies": policy,
            "ttl": ttl,
        })
        .as_object()
        .unwrap()
        .clone();

        let resp =
            test_write_api(core, token, format!("auth/{}/users/{}", path, username).as_str(), true, Some(user_data))
                .await;
        assert!(resp.is_ok());
    }

    async fn test_user_login(
        core: &Core,
        path: &str,
        username: &str,
        password: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        let login_data = json!({
            "password": password,
        })
        .as_object()
        .unwrap()
        .clone();

        let mut req = Request::new(format!("auth/{}/login/{}", path, username).as_str());
        req.operation = Operation::Write;
        req.body = Some(login_data);

        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_ok());
        if is_ok {
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
        }
        resp
    }

    #[tokio::test]
    async fn test_policy_http_api() {
        let (root_token, core) = test_rusty_vault_init("test_policy_http_api");
        let core = core.read().unwrap();

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/" {
                capabilities = ["read"]
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;

        // Read
        let policy1 = test_read_policy(&core, &root_token, policy1_name).await;
        assert!(policy1.is_ok());
        let policy1 = policy1.unwrap();
        assert!(policy1.is_some());
        let policy1 = policy1.unwrap();
        assert!(policy1.data.is_some());
        let policy1 = policy1.data.unwrap();
        assert_eq!(policy1["name"], policy1_name);
        assert_eq!(policy1["rules"], policy1_hcl.trim());

        // List
        let policies = test_list_api(&core, &root_token, "sys/policy", true).await;
        assert!(policies.is_ok());
        let policies = policies.unwrap();
        assert!(policies.is_some());
        let policies = policies.unwrap();
        assert!(policies.data.is_some());
        let policies = policies.data.unwrap();
        assert_eq!(policies["keys"], json!(["default", policy1_name, "root"]));
        assert_eq!(policies["policies"], json!(["default", policy1_name, "root"]));

        // Delete
        test_delete_policy(&core, &root_token, policy1_name).await;

        // Read again
        let policy1 = test_read_policy(&core, &root_token, policy1_name).await;
        let policy1 = policy1.unwrap();
        assert!(policy1.is_none());

        // List again
        let policies = test_list_api(&core, &root_token, "sys/policy", true).await;
        let policies = policies.unwrap().unwrap().data.unwrap();
        assert_eq!(policies["keys"], json!(["default", "root"]));
        assert_eq!(policies["policies"], json!(["default", "root"]));
    }

    #[tokio::test]
    async fn test_policy_acl_check() {
        let (root_token, core) = test_rusty_vault_init("test_policy_acl_check");
        let core = core.read().unwrap();

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/*" {
                capabilities = ["read"]
            }

            path "path1/kv1" {
                capabilities = ["read", "list", "create", "update", "delete"]
            }
        "#;
        let policy2_name = "policy2";
        let policy2_hcl = r#"
            path "path1/*" {
                capabilities = ["read", "list", "create", "update"]
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;
        test_write_policy(&core, &root_token, policy2_name, policy2_hcl).await;

        // Mount userpass auth
        test_mount_auth_api(&core, &root_token, "userpass", "up1").await;

        // Add user xxx with policy1, add user yyy with policy2
        test_write_user(&core, &root_token, "up1", "xxx", "123qwe!@#", policy1_name, 0).await;
        let resp = test_user_login(&core, "up1", "xxx", "123qwe!@#", true).await;
        assert!(resp.is_ok());
        let xxx_token = resp.unwrap().unwrap().auth.unwrap().client_token;
        test_write_user(&core, &root_token, "up1", "yyy", "123456", policy2_name, 0).await;
        let resp = test_user_login(&core, "up1", "yyy", "123456", true).await;
        assert!(resp.is_ok());
        let yyy_token = resp.unwrap().unwrap().auth.unwrap().client_token;

        // Mount kv to path1/ and path2/
        test_mount_api(&core, &root_token, "kv", "path1/").await;
        test_mount_api(&core, &root_token, "kv", "path2/").await;

        // User xxx write path path1/kv1 should succeed
        let data = json!({
            "aa": "bb",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(&core, &xxx_token, "path1/kv1", true, Some(data.clone())).await;
        assert!(resp.is_ok());

        // User xxx write path1/kv2 should fail
        let resp = test_write_api(&core, &xxx_token, "path1/kv2", false, Some(data.clone())).await;
        assert!(resp.is_err());

        // User yyy write path1/kv2 should succeed
        let resp = test_write_api(&core, &yyy_token, "path1/kv2", true, Some(data.clone())).await;
        assert!(resp.is_ok());

        // User xxx read path1/kv1 should succeed
        let resp = test_read_api(&core, &xxx_token, "path1/kv1", true).await;
        assert!(resp.is_ok());

        // User xxx read path1/kv2 should succeed
        let resp = test_read_api(&core, &xxx_token, "path1/kv2", true).await;
        assert!(resp.is_ok());

        // User yyy read path1/kv1 should succeed
        let resp = test_read_api(&core, &yyy_token, "path1/kv1", true).await;
        assert!(resp.is_ok());

        // User yyy read path1/kv2 should succeed
        let resp = test_read_api(&core, &yyy_token, "path1/kv2", true).await;
        assert!(resp.is_ok());

        // User xxx list path1/ should fail
        let resp = test_list_api(&core, &xxx_token, "path1", false).await;
        assert!(resp.is_err());

        // User yyy list path1/ should fail
        let resp = test_list_api(&core, &yyy_token, "path1", false).await;
        assert!(resp.is_err());

        // User yyy delete path1/kv1 should fail
        let resp = test_delete_api(&core, &yyy_token, "path1/kv1", false, None).await;
        assert!(resp.is_err());

        // User yyy delete path1/kv2 should fail
        let resp = test_delete_api(&core, &yyy_token, "path1/kv2", false, None).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_policy_acl_check_with_policy_parameters() {
        let (root_token, core) = test_rusty_vault_init("test_policy_acl_check_with_policy_parameters");
        let core = core.read().unwrap();

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/*" {
                capabilities = ["read", "list"]
            }

            path "path1/kv1" {
                capabilities = ["read", "list", "create", "update", "delete"]
                allowed_parameters = {"key1" = ["value1", "value2"], "key2" = ["value3", "value4"]}
                required_parameters = ["key1"]
            }

            path "path1/kv2" {
                capabilities = ["read", "list", "create", "update"]
                required_parameters = ["key1", "key2", "key3"]
            }

            path "path1/kv3" {
                capabilities = ["read", "list", "create", "update"]
                denied_parameters = {"*" = []}
            }

            path "path1/kv4" {
                capabilities = ["read", "list", "create", "update"]
                denied_parameters = {"key2" = ["value3", "value4"]}
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;

        // Mount userpass auth
        test_mount_auth_api(&core, &root_token, "userpass", "up1").await;

        // Add user xxx with policy1
        test_write_user(&core, &root_token, "up1", "xxx", "123qwe!@#", policy1_name, 0).await;
        let resp = test_user_login(&core, "up1", "xxx", "123qwe!@#", true).await;
        assert!(resp.is_ok());
        let xxx_token = resp.unwrap().unwrap().auth.unwrap().client_token;

        // Mount kv to path1/ and path2/
        test_mount_api(&core, &root_token, "kv", "path1/").await;

        // User xxx write path path1/kv1 with parameters key1=value1 should succeed
        let data = json!({
            "key1": "value1",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, Some(data.clone())).await;

        // User xxx write path path1/kv1 with parameters key1=value2 should succeed
        let data = json!({
            "key1": "value2",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, Some(data.clone())).await;

        // User xxx write path1/kv2 should fail
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, Some(data.clone())).await;

        // User xxx write path path1/kv1 with parameters key1=value1 and key2=value3 should succeed
        let data = json!({
            "key1": "value1",
            "key2": "value3",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, Some(data.clone())).await;

        // User xxx write path path1/kv1 with parameters key1=value1 and key2=value4 should succeed
        let data = json!({
            "key1": "value1",
            "key2": "value4",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, Some(data.clone())).await;

        // User xxx write path path1/kv1 with parameters key1=value2 and key2=value22 should fail
        let data = json!({
            "key1": "value2",
            "key2": "value22",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, Some(data.clone())).await;

        // User xxx read path1/kv1 without parameters should fail
        let _ = test_read_api(&core, &xxx_token, "path1/kv1", false).await;

        // User xxx list path1/ should fail
        let _ = test_list_api(&core, &xxx_token, "path1", false).await;

        // User xxx write path path1/kv1 with parameters key1=value3 should fail
        let data = json!({
            "key1": "value3",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, Some(data.clone())).await;

        // User xxx write path path1/kv1 with parameters key2=value3 (missing key1) should fail
        let data = json!({
            "key2": "value3",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, Some(data.clone())).await;

        // User xxx write path path1/kv2 with parameters key1 (missing key2 and key3) should fail
        let data = json!({
            "key1": "xx",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, Some(data.clone())).await;

        // User xxx write path path1/kv2 with parameters key1 and key2 (missing key3) should fail
        let data = json!({
            "key1": "xx",
            "key2": "yy",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, Some(data.clone())).await;

        // User xxx write path path1/kv2 with parameters key1、key2 and key3 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy",
            "key3": "zz",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", true, Some(data.clone())).await;

        // User xxx write path path1/kv2 with parameters key1、key2、key3 and other param should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy",
            "key3": "zz",
            "key4": "vv",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", true, Some(data.clone())).await;

        // User xxx write path path1/kv3 with parameters key1 should fail
        let data = json!({
            "key1": "xx",
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv3", false, Some(data.clone())).await;

        // User xxx write path path1/kv3 with parameters key1 should fail
        let data = json!({
            "key1": "xx",
            "key2": "yy"
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv3", false, Some(data.clone())).await;

        // User xxx write path path1/kv4 with parameters key1 should succeed
        let data = json!({
            "key1": "xx"
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", true, Some(data.clone())).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=yy should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy"
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", true, Some(data.clone())).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=value3 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "value3"
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", false, Some(data.clone())).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=value4 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "value4"
        })
        .as_object()
        .unwrap()
        .clone();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", false, Some(data.clone())).await;
    }
}
