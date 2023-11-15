use std::sync::Arc;
use regex::Regex;
use std::collections::HashMap;
use serde_json::{Value, Map};
use crate::errors::RvError;
use super::request::Request;
use super::response::Response;
use super::path::Path;
use super::secret::Secret;
use super::{Backend, Operation};

#[derive(Clone)]
pub struct LogicalBackend {
    pub paths: Vec<Arc<Path>>,
    pub paths_re: Vec<Regex>,
    pub root_paths: Arc<Vec<String>>,
    pub unauth_paths: Arc<Vec<String>>,
    pub help: String,
    pub secrets: Vec<Arc<Secret>>,
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
                    return operation.handle_request(self, req);
                    /*
                    let resp = operation.handle_request(self, req)?;
                    if resp.is_none() {
                        return Ok(Some(Response::new()));
                    }

                    return Ok(resp);
                    */
                }
            }

            //return Ok(None);
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
        }
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
    (@object $object:ident paths: [$($path:tt),*]) => {
        $(
            $object.paths.push(Arc::new(new_path!($path)));
        )*
    };
    (@object $object:ident unauth_paths: [$($unauth:expr),*]) => {
        $object.unauth_paths = Arc::new(vec![$($unauth.to_string()),*]);
    };
    (@object $object:ident root_paths: [$($root:expr),*]) => {
        $object.root_paths = Arc::new(vec![$($root.to_string()),*]);
    };
    (@object $object:ident help: $help:expr) => {
        $object.help = $help.to_string();
    };
    (@object $object:ident secrets: [$($secrets:tt),* $(,)?]) => {
        $(
            $object.secrets.push(Arc::new(new_secret!($secrets)));
        )*
    };
    (@object $object:ident () $($key:ident: $value:tt),*) => {
        $(
            new_logical_backend_internal!(@object $object $key: $value);
        )*
    };
    ({ $($tt:tt)+ }) => {
        {
            let mut backend = LogicalBackend::new();
            new_logical_backend_internal!(@object backend () $($tt)+);
            backend
        }
    };
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::sync::Arc;
    use std::collections::HashMap;
    use std::time::Duration;
    use go_defer::defer;
    use super::*;
    use crate::{new_path, new_path_internal, new_secret, new_secret_internal};
    use crate::storage::physical;
    use crate::storage::barrier_aes_gcm::AESGCMBarrier;
    use crate::logical::{Field, FieldType, PathOperation};

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
            unauth_paths: ["/login"],
            root_paths: ["/"],
            help: "help content"
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

        assert_eq!(logical_backend.paths_re.len(), 0);

        assert!(logical_backend.init().is_ok());

        assert_eq!(logical_backend.paths_re.len(), 2);

        let mut req = Request::new("/bar");
        req.operation = Operation::Write;

        assert!(logical_backend.handle_request(&mut req).is_err());

        req.storage = Some(Arc::new(barrier));
        assert!(logical_backend.handle_request(&mut req).is_ok());

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
