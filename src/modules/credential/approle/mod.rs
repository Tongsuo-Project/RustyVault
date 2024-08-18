//! The approle auth method allows machines or apps to authenticate with RustyVault-defined roles.
//! The open design of AppRole enables a varied set of workflows and configurations to handle
//! large numbers of apps. This auth method is oriented to automated workflows (machines and
//! services), and is less useful for human operators. We recommend using batch tokens with
//! the AppRole auth method.
//!
//! An "AppRole" represents a set of Vault policies and login constraints that must be met to
//! receive a token with those policies. The scope can be as narrow or broad as desired.
//! An AppRole can be created for a particular machine, or even a particular user on that
//! machine, or a service spread across machines. The credentials required for successful
//! login depend upon the constraints set on the AppRole associated with the credentials.
//!
//! ## Credentials/Constraints
//!
//! ### RoleID
//!
//! RoleID is an identifier that selects the AppRole against which the other credentials are
//! evaluated. When authenticating against this auth method's login endpoint, the RoleID is
//! a required argument (via `role_id`) at all times. By default, RoleIDs are unique UUIDs,
//! which allow them to serve as secondary secrets to the other credential information.
//! However, they can be set to particular values to match introspected information by the
//! client (for instance, the client's domain name).
//!
//! ### SecretID
//!
//! SecretID is a credential that is required by default for any login (via `secret_id`) and
//! is intended to always be secret. (For advanced usage, requiring a SecretID can be disabled
//! via an AppRole's `bind_secret_id` parameter, allowing machines with only knowledge of the
//! RoleID, or matching other set constraints, to fetch a token). SecretIDs can be created
//! against an AppRole either via generation of a 128-bit purely random UUID by the role
//! itself (`Pull` mode) or via specific, custom values (`Push` mode).
//! Similarly to tokens, SecretIDs have properties like usage-limit, TTLs and expirations.
//!
//! ### Further constraints
//!
//! `role_id` is a required credential at the login endpoint. AppRole pointed to by the `role_id`
//! will have constraints set on it. This dictates other `required` credentials for login.
//! The `bind_secret_id` constraint requires `secret_id` to be presented at the login endpoint.
//! Going forward, this auth method can support more constraint parameters to support varied set
//! of Apps.  Some constraints will not require a credential, but still enforce constraints for login.
//! For example, `secret_id_bound_cidrs` will only allow logins coming from IP addresses belonging
//! to configured CIDR blocks on the AppRole.

use std::sync::{atomic::AtomicU32, Arc, RwLock};

use as_any::Downcast;
use derive_more::Deref;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend, Request, Response},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
    utils::{locks::Locks, salt::Salt},
};

pub mod path_login;
pub mod path_role;
pub mod path_tidy_secret_id;
pub mod validation;

const HMAC_INPUT_LEN_MAX: usize = 4096;

const SECRET_ID_PREFIX: &str = "secret_id/";
const SECRET_ID_LOCAL_PREFIX: &str = "secret_id_local/";
const SECRET_ID_ACCESSOR_PREFIX: &str = "accessor/";
const SECRET_ID_ACCESSOR_LOCAL_PREFIX: &str = "accessor_local/";

static APPROLE_BACKEND_HELP: &str = r#"
Any registered Role can authenticate itself with RustyVault. The credentials
depends on the constraints that are set on the Role. One common required
credential is the 'role_id' which is a unique identifier of the Role.
It can be retrieved from the 'role/<appname>/role-id' endpoint.

The default constraint configuration is 'bind_secret_id', which requires
the credential 'secret_id' to be presented during login. Refer to the
documentation for other types of constraints.`
"#;

#[derive(Deref)]
pub struct AppRoleModule {
    pub name: String,
    #[deref]
    pub backend: Arc<AppRoleBackend>,
}

pub struct AppRoleBackendInner {
    pub core: Arc<RwLock<Core>>,
    pub salt: RwLock<Option<Salt>>,
    pub role_locks: Locks,
    pub role_id_locks: Locks,
    pub secret_id_locks: Locks,
    pub secret_id_accessor_locks: Locks,
    pub tidy_secret_id_cas_guard: AtomicU32,
}

#[derive(Deref)]
pub struct AppRoleBackend {
    #[deref]
    pub inner: Arc<AppRoleBackendInner>,
}

impl AppRoleBackend {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { inner: Arc::new(AppRoleBackendInner::new(core)) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let approle_backend_ref = Arc::clone(&self.inner);

        let mut backend = new_logical_backend!({
            unauth_paths: ["login"],
            auth_renew_handler: approle_backend_ref.renew_path_login,
            help: APPROLE_BACKEND_HELP,
        });

        let role_paths = self.role_paths();
        backend.paths.extend(role_paths.into_iter().map(Arc::new));
        backend.paths.push(Arc::new(self.login_path()));

        backend.paths.push(Arc::new(self.role_path()));
        backend.paths.push(Arc::new(self.tidy_secret_id_path()));

        backend
    }
}

impl AppRoleBackendInner {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self {
            core,
            salt: RwLock::new(None),
            role_locks: Locks::new(),
            role_id_locks: Locks::new(),
            secret_id_locks: Locks::new(),
            secret_id_accessor_locks: Locks::new(),
            tidy_secret_id_cas_guard: AtomicU32::new(0),
        }
    }

    pub fn renew_path_login(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl AppRoleModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "approle".to_string(),
            backend: Arc::new(AppRoleBackend::new(Arc::clone(core.self_ref.as_ref().unwrap()))),
        }
    }
}

impl Module for AppRoleModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let approle = Arc::clone(&self.backend);
        let approle_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut approle_backend = approle.new_backend();
            approle_backend.init()?;
            Ok(Arc::new(approle_backend))
        };

        if let Some(module) = core.module_manager.get_module("auth") {
            let auth_mod = module.read()?;
            if let Some(auth_module) = auth_mod.as_ref().downcast_ref::<AuthModule>() {
                return auth_module.add_auth_backend("approle", Arc::new(approle_backend_new_func));
            } else {
                log::error!("downcast auth module failed!");
            }
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    fn init(&mut self, core: &Core) -> Result<(), RvError> {
        if core.get_system_view().is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let salt = Salt::new(Some(core.get_system_storage()), None)?;

        let mut approle_salt = self.backend.inner.salt.write()?;
        *approle_salt = Some(salt);

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        if let Some(module) = core.module_manager.get_module("auth") {
            let auth_mod = module.read()?;
            if let Some(auth_module) = auth_mod.as_ref().downcast_ref::<AuthModule>() {
                return auth_module.delete_auth_backend("approle");
            } else {
                log::error!("downcast auth module failed!");
            }
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        default::Default,
        env, fs,
        sync::{Arc, RwLock},
    };

    use go_defer::defer;
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::{
        core::{Core, SealConfig},
        logical::{field::FieldTrait, Operation, Request},
        storage,
    };

    fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Read;
        req.client_token = token.to_string();
        let resp = core.handle_request(&mut req);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_write_api(
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
        println!("resp: {:?}", resp);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_mount_approle_auth(core: Arc<RwLock<Core>>, token: &str, path: &str) {
        let core = core.read().unwrap();

        let auth_data = json!({
            "type": "approle",
        })
        .as_object()
        .unwrap()
        .clone();

        let resp = test_write_api(&core, token, format!("sys/auth/{}", path).as_str(), true, Some(auth_data));
        assert!(resp.is_ok());
    }

    fn test_read_role(
        core: Arc<RwLock<Core>>,
        token: &str,
        path: &str,
        role_name: &str,
    ) -> Result<Option<Response>, RvError> {
        let core = core.read().unwrap();

        let resp = test_read_api(&core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true);
        assert!(resp.is_ok());
        resp
    }

    fn generate_secret_id(core: Arc<RwLock<Core>>, token: &str, role_name: &str) -> (String, String) {
        let core = core.read().unwrap();
        let resp =
            test_write_api(&core, token, format!("auth/approle/role/{}/secret-id", role_name).as_str(), true, None);
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        let secret_id = resp_data["secret_id"].as_str().unwrap();
        let secret_id_accessor = resp_data["secret_id_accessor"].as_str().unwrap();

        (secret_id.to_string(), secret_id_accessor.to_string())
    }

    fn test_login(
        core: Arc<RwLock<Core>>,
        path: &str,
        role_id: &str,
        secret_id: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        let core = core.read().unwrap();

        let data = json!({
            "role_id": role_id,
            "secret_id": secret_id,
        })
        .as_object()
        .unwrap()
        .clone();

        let mut req = Request::new(format!("auth/{}/login", path).as_str());
        req.operation = Operation::Write;
        req.body = Some(data);

        let resp = core.handle_request(&mut req);
        if is_ok {
            assert!(resp.is_ok());
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
            let resp = resp.as_ref().unwrap();
            assert!(resp.auth.is_some());
        } else {
            assert!(resp.is_err());
        }

        resp
    }

    fn test_approle(c: Arc<RwLock<Core>>, token: &str, path: &str, role_name: &str) {
        let core = c.read().unwrap();

        // Create a role
        let resp = test_write_api(&core, token, format!("auth/{}/role/{}", path, role_name).as_str(), true, None);
        assert!(resp.is_ok());

        // Get the role-id
        let resp = test_read_api(&core, token, format!("auth/{}/role/{}/role-id", path, role_name).as_str(), true);
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data;
        let role_id = resp_data.unwrap()["role_id"].clone();
        let role_id = role_id.as_str().unwrap();

        // Create a secret-id
        let (secret_id, secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Destroy secret ID accessor
        let data = json!({
            "secret_id_accessor": secret_id_accessor,
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}/secret-id-accessor/destroy", path, role_name).as_str(),
            true,
            Some(data),
        );
        assert!(resp.is_ok());

        // Login again using the accessor's corresponding secret ID should fail
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, false);

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Destroy secret ID
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name).as_str(),
            true,
            Some(data),
        );
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, false);

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Destroy the secret ID using lower cased role name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name.to_lowercase()).as_str(),
            true,
            Some(data),
        );
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, false);

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Destroy the secret ID using upper cased role name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, role_name.to_uppercase()).as_str(),
            true,
            Some(data),
        );
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, false);

        // Generate another secret ID
        let (secret_id, _secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Destroy the secret ID using mixed case name
        let data = json!({
            "secret_id": secret_id,
        })
        .as_object()
        .unwrap()
        .clone();
        let mut mixed_case_name = role_name.to_string();
        if let Some(first_char) = mixed_case_name.get_mut(0..1) {
            let inverted_case_char = if first_char.chars().next().unwrap().is_uppercase() {
                first_char.to_lowercase()
            } else {
                first_char.to_uppercase()
            };
            mixed_case_name.replace_range(0..1, &inverted_case_char);
        }
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}/secret-id/destroy", path, mixed_case_name).as_str(),
            true,
            Some(data),
        );
        assert!(resp.is_ok());

        // Login again using the same secret ID should fail
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, false);
    }

    fn test_approle_role_service(c: Arc<RwLock<Core>>, token: &str, path: &str, role_name: &str) {
        let core = c.read().unwrap();

        // Create a role
        let mut data = json!({
            "bind_secret_id":       true,
            "secret_id_num_uses":   0,
            "secret_id_ttl":        "10m",
            "token_policies":       "policy",
            "token_ttl":            "5m",
            "token_max_ttl":        "10m",
            "token_num_uses":       2,
            "token_type":           "default",
        })
        .as_object()
        .unwrap()
        .clone();
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}", path, role_name).as_str(),
            true,
            Some(data.clone()),
        );
        assert!(resp.is_ok());

        // Get the role field
        let resp = test_read_role(c.clone(), token, path, role_name);
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["bind_secret_id"].as_bool().unwrap(), data["bind_secret_id"].as_bool().unwrap());
        assert_eq!(resp_data["secret_id_num_uses"].as_i64().unwrap(), data["secret_id_num_uses"].as_i64().unwrap());
        assert_eq!(
            resp_data["secret_id_ttl"].as_u64().unwrap(),
            data["secret_id_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(
            resp_data["token_policies"].as_comma_string_slice().unwrap(),
            data["token_policies"].as_comma_string_slice().unwrap()
        );
        assert_eq!(resp_data["token_ttl"].as_u64().unwrap(), data["token_ttl"].as_duration().unwrap().as_secs());
        assert_eq!(
            resp_data["token_max_ttl"].as_u64().unwrap(),
            data["token_max_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(resp_data["token_num_uses"].as_i64().unwrap(), data["token_num_uses"].as_i64().unwrap());
        assert_eq!(resp_data["token_type"].as_str().unwrap(), data["token_type"].as_str().unwrap());

        // Update the role
        data["token_num_uses"] = Value::from(0);
        data["token_type"] = Value::from("batch");
        let resp = test_write_api(
            &core,
            token,
            format!("auth/{}/role/{}", path, role_name).as_str(),
            true,
            Some(data.clone()),
        );
        assert!(resp.is_ok());

        // Get the role field
        let resp = test_read_role(c.clone(), token, path, role_name);
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        assert_eq!(resp_data["bind_secret_id"].as_bool().unwrap(), data["bind_secret_id"].as_bool().unwrap());
        assert_eq!(resp_data["secret_id_num_uses"].as_i64().unwrap(), data["secret_id_num_uses"].as_i64().unwrap());
        assert_eq!(
            resp_data["secret_id_ttl"].as_u64().unwrap(),
            data["secret_id_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(
            resp_data["token_policies"].as_comma_string_slice().unwrap(),
            data["token_policies"].as_comma_string_slice().unwrap()
        );
        assert_eq!(resp_data["token_ttl"].as_u64().unwrap(), data["token_ttl"].as_duration().unwrap().as_secs());
        assert_eq!(
            resp_data["token_max_ttl"].as_u64().unwrap(),
            data["token_max_ttl"].as_duration().unwrap().as_secs()
        );
        assert_eq!(resp_data["token_num_uses"].as_i64().unwrap(), data["token_num_uses"].as_i64().unwrap());
        assert_eq!(resp_data["token_type"].as_str().unwrap(), data["token_type"].as_str().unwrap());

        // Get the role-id
        let resp = test_read_api(&core, token, format!("auth/{}/role/{}/role-id", path, role_name).as_str(), true);
        assert!(resp.is_ok());
        let resp_data = resp.unwrap().unwrap().data;
        let role_id = resp_data.unwrap()["role_id"].clone();
        let role_id = role_id.as_str().unwrap();

        // Create a secret-id
        let (secret_id, _secret_id_accessor) = generate_secret_id(Arc::clone(&c), token, role_name);

        // Ensure login works
        let _ = test_login(Arc::clone(&c), path, role_id, &secret_id, true);

        // Get the role field
        let resp = test_read_role(c.clone(), token, path, role_name);
        let resp_data = resp.unwrap().unwrap().data.unwrap();
        println!("resp_data: {:?}", resp_data);
    }

    fn rusty_vault_init(dir: &str) -> (String, Arc<RwLock<Core>>) {
        let root_token;

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string()));

        let backend = storage::new_backend("file", &conf).unwrap();

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

    #[test]
    fn test_approle_module() {
        let dir = env::temp_dir().join("rusty_vault_credential_approle_module");
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let (root_token, core) = rusty_vault_init(dir.to_string_lossy().into_owned().as_str());

        // Mount approle auth to path: auth/approle
        test_mount_approle_auth(core.clone(), &root_token, "approle");

        test_approle(core.clone(), &root_token, "approle", "samplerolename");
        test_approle(core.clone(), &root_token, "approle", "SAMPLEROLENAME");
        test_approle(core.clone(), &root_token, "approle", "SampleRoleName");

        test_approle_role_service(core.clone(), &root_token, "approle", "testrole");
    }
}
