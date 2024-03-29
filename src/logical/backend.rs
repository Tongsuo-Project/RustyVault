use std::{collections::HashMap, sync::Arc};

use regex::Regex;
use serde_json::{Map, Value};

use super::{path::Path, request::Request, response::Response, secret::Secret, FieldType, Backend, Operation};
use crate::errors::RvError;

type BackendOperationHandler = dyn Fn(&dyn Backend, &mut Request) -> Result<Option<Response>, RvError> + Send + Sync;

#[derive(Clone)]
pub struct LogicalBackend {
    pub paths: Vec<Arc<Path>>,
    pub paths_re: Vec<Regex>,
    pub root_paths: Arc<Vec<String>>,
    pub unauth_paths: Arc<Vec<String>>,
    pub help: String,
    pub secrets: Vec<Arc<Secret>>,
    pub auth_renew_handler: Option<Arc<BackendOperationHandler>>,
}

impl Backend for LogicalBackend {
    fn init(&mut self) -> Result<(), RvError> {
        if self.paths.len() == self.paths_re.len() {
            return Ok(());
        }

        for path in &self.paths {
            let mut pattern = path.pattern.clone();
            if !path.pattern.starts_with('^') {
                pattern = format!("^{}", &pattern);
            }

            if !path.pattern.ends_with('$') {
                pattern = format!("{}$", &pattern);
            }

            let re = Regex::new(&pattern)?;
            self.paths_re.push(re);
        }

        Ok(())
    }

    fn setup(&self, _key: &str) -> Result<(), RvError> {
        Ok(())
    }

    fn cleanup(&self) -> Result<(), RvError> {
        Ok(())
    }

    fn get_unauth_paths(&self) -> Option<Arc<Vec<String>>> {
        Some(self.unauth_paths.clone())
    }

    fn get_root_paths(&self) -> Option<Arc<Vec<String>>> {
        Some(self.root_paths.clone())
    }

    fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.storage.is_none() {
            return Err(RvError::ErrRequestNotReady);
        }

        match req.operation {
            Operation::Renew | Operation::Revoke => {
                return self.handle_revoke_renew(req);
            }
            _ => {}
        }

        if req.path == "" && req.operation == Operation::Help {
            return self.handle_root_help(req);
        }

        if let Some((path, captures)) = self.match_path(&req.path) {
            if captures.len() != 0 {
                let mut data = Map::new();
                captures.iter().for_each(|(key, value)| {
                    data.insert(key.to_string(), Value::String(value.to_string()));
                });
                req.data = Some(data);
            }

            req.match_path = Some(path.clone());
            for operation in &path.operations {
                if operation.op == req.operation {
                    let ret = operation.handle_request(self, req);
                    self.clear_secret_field(req);
                    return ret;
                }
            }

            return Err(RvError::ErrLogicalOperationUnsupported);
        }

        Err(RvError::ErrLogicalPathUnsupported)
    }

    fn secret(&self, key: &str) -> Option<&Arc<Secret>> {
        self.secrets.iter().find(|s| s.secret_type == key)
    }
}

impl LogicalBackend {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            paths_re: Vec::new(),
            root_paths: Arc::new(Vec::new()),
            unauth_paths: Arc::new(Vec::new()),
            help: String::new(),
            secrets: Vec::new(),
            auth_renew_handler: None,
        }
    }

    pub fn handle_auth_renew(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if self.auth_renew_handler.is_none() {
            log::error!("this auth type doesn't support renew");
            return Err(RvError::ErrLogicalOperationUnsupported);
        }

        (self.auth_renew_handler.as_ref().unwrap())(self, req)
    }

    pub fn handle_revoke_renew(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.operation == Operation::Renew && req.auth.is_some() {
            return self.handle_auth_renew(req);
        }

        if req.secret.is_none() {
            log::error!("request has no secret");
            return Ok(None);
        }

        if let Some(raw_secret_type) = req.secret.as_ref().unwrap().internal_data.get("secret_type") {
            if let Some(secret_type) = raw_secret_type.as_str() {
                if let Some(secret) = self.secret(secret_type) {
                    match req.operation {
                        Operation::Renew => {
                            return secret.renew(self, req);
                        }
                        Operation::Revoke => {
                            return secret.revoke(self, req);
                        }
                        _ => {
                            log::error!("invalid operation for revoke/renew: {}", req.operation);
                            return Ok(None);
                        }
                    }
                }
            }
        }

        log::error!("secret is unsupported by this backend");
        return Ok(None);
    }

    pub fn handle_root_help(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn match_path(&self, path: &str) -> Option<(Arc<Path>, HashMap<String, String>)> {
        for (i, re) in self.paths_re.iter().enumerate() {
            if let Some(matches) = re.captures(path) {
                let mut captures = HashMap::new();
                let path = self.paths[i].clone();
                for (i, name) in re.capture_names().enumerate() {
                    if let Some(name) = name {
                        captures.insert(name.to_string(), matches[i].to_string());
                    }
                }

                return Some((path, captures));
            }
        }

        None
    }

    fn clear_secret_field(&self, req: &mut Request) {
        for path in &self.paths {
            for (key, field) in &path.fields {
                if field.field_type == FieldType::SecretStr {
                    req.clear_data(key);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! new_logical_backend {
    ($($tt:tt)*) => {
        new_logical_backend_internal!($($tt)*)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! new_logical_backend_internal {
    (@object $object:ident () {}) => {
    };
    (@object $object:ident () {paths: [$($path:tt),*], $($rest:tt)*}) => {
        $(
            $object.paths.push(Arc::new(new_path!($path)));
        )*
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {unauth_paths: [$($unauth:expr),*], $($rest:tt)*}) => {
        $object.unauth_paths = Arc::new(vec![$($unauth.to_string()),*]);
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {root_paths: [$($root:expr),*], $($rest:tt)*}) => {
        $object.root_paths = Arc::new(vec![$($root.to_string()),*]);
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {help: $help:expr, $($rest:tt)*}) => {
        $object.help = $help.to_string();
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {secrets: [$($secrets:tt),* $(,)?], $($rest:tt)*}) => {
        $(
            $object.secrets.push(Arc::new(new_secret!($secrets)));
        )*
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {auth_renew_handler: $handler_obj:ident$(.$handler_method:ident)*, $($rest:tt)*}) => {
        $object.auth_renew_handler = Some(Arc::new(move |backend: &dyn Backend, req: &mut Request| -> Result<Option<Response>, RvError> {
            $handler_obj$(.$handler_method)*(backend, req)
        }));
        new_logical_backend_internal!(@object $object () {$($rest)*});
    };
    ({ $($tt:tt)+ }) => {
        {
            let mut backend = LogicalBackend::new();
            new_logical_backend_internal!(@object backend () {$($tt)+});
            backend
        }
    };
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, env, fs, sync::Arc, time::Duration};

    use go_defer::defer;
    use serde_json::json;

    use super::*;
    use crate::{
        logical::{Field, FieldType, PathOperation},
        new_fields, new_fields_internal, new_path, new_path_internal, new_secret, new_secret_internal,
        storage::{barrier_aes_gcm::AESGCMBarrier, physical},
    };

    struct MyTest;

    impl MyTest {
        pub fn new() -> Self {
            MyTest
        }

        pub fn noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
            Ok(None)
        }
    }

    #[test]
    fn test_logical_backend_match_path() {
        let path = "/(?P<aa>.+?)/(?P<bb>.+)";
        let mut backend = LogicalBackend::new();
        backend.paths.push(Arc::new(Path::new(path)));
        assert!(backend.init().is_ok());
        let capture = backend.match_path("/aa/bb/cc");
        assert!(capture.is_some());
        let (p, cap) = capture.unwrap();
        assert_eq!(p.pattern, path.to_string());
        let aa = cap.get("aa");
        assert!(aa.is_some());
        assert_eq!(aa.unwrap(), "aa");
        let bb = cap.get("bb");
        assert!(bb.is_some());
        assert_eq!(bb.unwrap(), "bb/cc");
    }

    pub fn renew_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn revoke_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    #[test]
    fn test_logical_backend_api() {
        let dir = env::temp_dir().join("rusty_vault_test_logical_api");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let t = MyTest::new();

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = AESGCMBarrier::new(Arc::clone(&backend));

        let mut logical_backend = new_logical_backend!({
            paths: [
                {
                    pattern: "/(?P<bar>.+?)",
                    fields: {
                        "mytype": {
                            field_type: FieldType::Int,
                            description: "haha"
                        },
                        "mypath": {
                            field_type: FieldType::Str,
                            description: "hehe"
                        },
                        "mypassword": {
                            field_type: FieldType::SecretStr,
                            description: "password"
                        }
                    },
                    operations: [
                        {op: Operation::Read, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError>
                            {
                                Ok(None)
                            }
                        },
                        {op: Operation::Write, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                Ok(Some(Response::new()))
                            }
                        },
                        {op: Operation::Delete, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                Err(RvError::ErrUnknown)
                            }
                        }
                    ]
                },
                {
                    pattern: "/(?P<foo>.+?)/(?P<goo>.+)",
                    fields: {
                        "myflag": {
                            field_type: FieldType::Bool,
                            description: "hoho"
                        }
                    },
                    operations: [
                        {op: Operation::Read, raw_handler: |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                                 Ok(None)
                             }
                        }
                    ]
                }
            ],
            secrets: [{
                secret_type: "kv",
                default_duration: 60,
                renew_handler: renew_noop_handler,
                revoke_handler: revoke_noop_handler,
            }, {
                secret_type: "test",
                default_duration: 120,
                renew_handler: renew_noop_handler,
                revoke_handler: revoke_noop_handler,
            }],
            auth_renew_handler: t.noop,
            unauth_paths: ["/login"],
            root_paths: ["/"],
            help: "help content",
        });

        let mut req = Request::new("/");

        assert_eq!(logical_backend.paths.len(), 2);
        assert_eq!(&logical_backend.paths[0].pattern, "/(?P<bar>.+?)");
        assert!(logical_backend.paths[0].fields.get("mytype").is_some());
        assert_eq!(logical_backend.paths[0].fields["mytype"].field_type, FieldType::Int);
        assert_eq!(logical_backend.paths[0].fields["mytype"].description, "haha");
        assert!(logical_backend.paths[0].fields.get("mypath").is_some());
        assert_eq!(logical_backend.paths[0].fields["mypath"].field_type, FieldType::Str);
        assert_eq!(logical_backend.paths[0].fields["mypath"].description, "hehe");
        assert!(logical_backend.paths[0].fields.get("xxfield").is_none());
        assert_eq!(logical_backend.paths[0].operations[0].op, Operation::Read);
        assert_eq!(logical_backend.paths[0].operations[1].op, Operation::Write);
        assert_eq!(logical_backend.paths[0].operations.len(), 3);
        assert!((logical_backend.paths[0].operations[0].handler)(&logical_backend, &mut req).is_ok());
        assert!((logical_backend.paths[0].operations[0].handler)(&logical_backend, &mut req).unwrap().is_none());
        assert!((logical_backend.paths[0].operations[1].handler)(&logical_backend, &mut req).is_ok());
        assert!((logical_backend.paths[0].operations[1].handler)(&logical_backend, &mut req).unwrap().is_some());
        assert!((logical_backend.paths[0].operations[2].handler)(&logical_backend, &mut req).is_err());

        assert_eq!(&logical_backend.paths[1].pattern, "/(?P<foo>.+?)/(?P<goo>.+)");
        assert_eq!(logical_backend.paths[1].fields["myflag"].field_type, FieldType::Bool);
        assert_eq!(logical_backend.paths[1].fields["myflag"].description, "hoho");
        assert_eq!(logical_backend.paths[1].operations.len(), 1);
        assert_eq!(logical_backend.paths[1].operations[0].op, Operation::Read);
        assert!((logical_backend.paths[1].operations[0].handler)(&logical_backend, &mut req).is_ok());
        assert!((logical_backend.paths[1].operations[0].handler)(&logical_backend, &mut req).unwrap().is_none());

        assert_eq!(logical_backend.unauth_paths.len(), 1);
        assert_eq!(&logical_backend.unauth_paths[0], "/login");
        assert_eq!(logical_backend.root_paths.len(), 1);
        assert_eq!(&logical_backend.root_paths[0], "/");
        assert_eq!(&logical_backend.help, "help content");

        assert!(logical_backend.auth_renew_handler.is_some());

        assert_eq!(logical_backend.paths_re.len(), 0);

        assert!(logical_backend.init().is_ok());

        assert_eq!(logical_backend.paths_re.len(), 2);

        let mut req = Request::new("/bar");
        req.operation = Operation::Write;

        assert!(logical_backend.handle_request(&mut req).is_err());

        let body: Map<String, Value> = json!({
            "mytype": 1,
            "mypath": "/pp",
            "mypassword": "123qwe",
        }).as_object().unwrap().clone();
        req.body = Some(body);
        req.storage = Some(Arc::new(barrier));
        assert!(logical_backend.handle_request(&mut req).is_ok());
        let mypassword = req.body.as_ref().unwrap().get("mypassword");
        assert!(mypassword.is_some());
        assert_eq!(mypassword.unwrap(), "");

        let unauth_paths = logical_backend.get_unauth_paths();
        assert!(unauth_paths.is_some());
        let unauth_paths = unauth_paths.as_ref().unwrap();
        assert_eq!(unauth_paths.len(), 1);
        assert_eq!(&unauth_paths[0], "/login");

        let root_paths = logical_backend.get_root_paths();
        assert!(root_paths.is_some());
        let root_paths = root_paths.as_ref().unwrap();
        assert_eq!(root_paths.len(), 1);
        assert_eq!(&root_paths[0], "/");

        assert_eq!(logical_backend.secrets.len(), 2);
        assert!(logical_backend.secret("kv").is_some());
        assert!(logical_backend.secret("test").is_some());
        assert!(logical_backend.secret("test_no").is_none());
        assert!(logical_backend.secret("kv").unwrap().renew(&logical_backend, &mut req).is_ok());
        assert!(logical_backend.secret("kv").unwrap().revoke(&logical_backend, &mut req).is_ok());
    }
}
