use std::{
    ops::Deref,
    sync::{Arc, RwLock},
};

use as_any::Downcast;

use crate::{
    core::Core,
    errors::RvError,
    logical::{Backend, LogicalBackend, Request, Response},
    modules::{auth::AuthModule, Module},
    new_logical_backend, new_logical_backend_internal,
};

pub mod path_login;
pub mod path_users;

static USERPASS_BACKEND_HELP: &str = r#"
The "userpass" credential provider allows authentication using a combination of
a username and password. No additional factors are supported.

The username/password combination is configured using the "users/" endpoints by
a user with root access. Authentication is then done by supplying the two fields
for "login".
"#;

pub struct UserPassModule {
    pub name: String,
    pub backend: Arc<UserPassBackend>,
}

pub struct UserPassBackendInner {
    pub core: Arc<RwLock<Core>>,
}

pub struct UserPassBackend {
    pub inner: Arc<UserPassBackendInner>,
}

impl Deref for UserPassBackend {
    type Target = UserPassBackendInner;

    fn deref(&self) -> &UserPassBackendInner {
        &self.inner
    }
}

impl UserPassBackend {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { inner: Arc::new(UserPassBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let userpass_backend_ref = Arc::clone(&self.inner);

        let mut backend = new_logical_backend!({
            unauth_paths: ["login/*"],
            auth_renew_handler: userpass_backend_ref.renew_path_login,
            help: USERPASS_BACKEND_HELP,
        });

        backend.paths.push(Arc::new(self.users_path()));
        backend.paths.push(Arc::new(self.user_list_path()));
        backend.paths.push(Arc::new(self.user_password_path()));
        backend.paths.push(Arc::new(self.login_path()));

        backend
    }
}

impl UserPassBackendInner {
    pub fn renew_path_login(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl UserPassModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "userpass".to_string(),
            backend: Arc::new(UserPassBackend::new(Arc::clone(core.self_ref.as_ref().unwrap()))),
        }
    }
}

impl Module for UserPassModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let userpass = Arc::clone(&self.backend);
        let userpass_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut userpass_backend = userpass.new_backend();
            userpass_backend.init()?;
            Ok(Arc::new(userpass_backend))
        };

        if let Some(module) = core.module_manager.get_module("auth") {
            let auth_mod = module.read()?;
            if let Some(auth_module) = auth_mod.as_ref().downcast_ref::<AuthModule>() {
                return auth_module.add_auth_backend("userpass", Arc::new(userpass_backend_new_func));
            } else {
                log::error!("downcast auth module failed!");
            }
        } else {
            log::error!("get auth module failed!");
        }

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        if let Some(module) = core.module_manager.get_module("auth") {
            let auth_mod = module.read()?;
            if let Some(auth_module) = auth_mod.as_ref().downcast_ref::<AuthModule>() {
                return auth_module.delete_auth_backend("userpass");
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
        time::Duration,
    };

    use go_defer::defer;
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::{
        core::{Core, SealConfig},
        logical::{Operation, Request},
        storage::{barrier_aes_gcm, physical},
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
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_delete_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Delete;
        req.client_token = token.to_string();
        let resp = core.handle_request(&mut req);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_mount_userpass_auth(core: Arc<RwLock<Core>>, token: &str, path: &str) {
        let core = core.read().unwrap();

        let auth_data = json!({
            "type": "userpass",
        })
        .as_object()
        .unwrap()
        .clone();

        let resp = test_write_api(&core, token, format!("sys/auth/{}", path).as_str(), true, Some(auth_data));
        assert!(resp.is_ok());
    }

    fn test_write_user(core: Arc<RwLock<Core>>, token: &str, path: &str, username: &str, password: &str, ttl: i32) {
        let core = core.read().unwrap();

        let user_data = json!({
            "password": password,
            "ttl": ttl,
        })
        .as_object()
        .unwrap()
        .clone();

        let resp =
            test_write_api(&core, token, format!("auth/{}/users/{}", path, username).as_str(), true, Some(user_data));
        assert!(resp.is_ok());
    }

    fn test_read_user(core: Arc<RwLock<Core>>, token: &str, username: &str) -> Result<Option<Response>, RvError> {
        let core = core.read().unwrap();

        let resp = test_read_api(&core, token, format!("auth/pass/users/{}", username).as_str(), true);
        assert!(resp.is_ok());
        resp
    }

    fn test_delete_user(core: Arc<RwLock<Core>>, token: &str, username: &str) {
        let core = core.read().unwrap();

        let resp = test_delete_api(&core, token, format!("auth/pass/users/{}", username).as_str(), true);
        assert!(resp.is_ok());
    }

    fn test_login(
        core: Arc<RwLock<Core>>,
        path: &str,
        username: &str,
        password: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        let core = core.read().unwrap();

        let login_data = json!({
            "password": password,
        })
        .as_object()
        .unwrap()
        .clone();

        let mut req = Request::new(format!("auth/{}/login/{}", path, username).as_str());
        req.operation = Operation::Write;
        req.body = Some(login_data);

        let resp = core.handle_request(&mut req);
        assert!(resp.is_ok());
        if is_ok {
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
        }
        resp
    }

    #[test]
    fn test_userpass_module() {
        let dir = env::temp_dir().join("rusty_vault_credential_userpass_module");
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

            assert!(unsealed);
        }

        {
            println!("root_token: {:?}", root_token);

            // mount userpass auth to path: auth/pass
            test_mount_userpass_auth(Arc::clone(&c), &root_token, "pass");
            test_write_user(Arc::clone(&c), &root_token, "pass", "test", "123qwe!@#", 0);
            let resp = test_read_user(Arc::clone(&c), &root_token, "test").unwrap();
            assert!(resp.is_some());

            test_delete_user(Arc::clone(&c), &root_token, "test");
            let resp = test_read_user(Arc::clone(&c), &root_token, "test").unwrap();
            assert!(resp.is_none());

            test_write_user(Arc::clone(&c), &root_token, "pass", "test", "123qwe!@#", 0);
            let _ = test_login(Arc::clone(&c), "pass", "test", "123qwe!@#", true);
            let _ = test_login(Arc::clone(&c), "pass", "test", "xxxxxxx", false);
            let _ = test_login(Arc::clone(&c), "pass", "xxxx", "123qwe!@#", false);
            let resp = test_login(Arc::clone(&c), "pass", "test", "123qwe!@#", true);
            let login_auth = resp.unwrap().unwrap().auth.unwrap();
            let test_client_token = login_auth.client_token.clone();
            {
                let c1 = Arc::clone(&c);
                let c2 = c1.read().unwrap();
                let resp = test_read_api(&c2, &test_client_token, "sys/mounts", true);
                println!("test mounts resp: {:?}", resp);
                assert!(resp.unwrap().is_some());
            }

            test_delete_user(Arc::clone(&c), &root_token, "test");
            let resp = test_login(Arc::clone(&c), "pass", "test", "123qwe!@#", false);
            let login_resp = resp.unwrap().unwrap();
            assert!(login_resp.auth.is_none());

            test_write_user(Arc::clone(&c), &root_token, "pass", "test2", "123qwe", 5);
            let resp = test_read_user(Arc::clone(&c), &root_token, "test").unwrap();
            assert!(resp.is_none());
            let resp = test_login(Arc::clone(&c), "pass", "test2", "123qwe", true);
            let login_auth = resp.unwrap().unwrap().auth.unwrap();
            println!("user login_auth: {:?}", login_auth);
            assert_eq!(login_auth.lease.ttl.as_secs(), 5);

            println!("wait 7s");
            std::thread::sleep(Duration::from_secs(7));
            let test_client_token = login_auth.client_token.clone();
            {
                let c1 = Arc::clone(&c);
                let c2 = c1.read().unwrap();
                let resp = test_read_api(&c2, &test_client_token, "sys/mounts", false);
                println!("test mounts resp: {:?}", resp);
            }

            // mount userpass auth to path: auth/testpass
            test_mount_userpass_auth(Arc::clone(&c), &root_token, "testpass");
            test_write_user(Arc::clone(&c), &root_token, "testpass", "testuser", "123qwe!@#", 0);
            let resp = test_login(Arc::clone(&c), "testpass", "testuser", "123qwe!@#", true);
            let login_auth = resp.unwrap().unwrap().auth.unwrap();
            let test_client_token = login_auth.client_token.clone();
            println!("test_client_token: {}", test_client_token);
            {
                let c1 = Arc::clone(&c);
                let c2 = c1.read().unwrap();
                let resp = test_read_api(&c2, &test_client_token, "sys/mounts", true);
                println!("test mounts resp: {:?}", resp);
                assert!(resp.unwrap().is_some());
            }
        }
    }
}
