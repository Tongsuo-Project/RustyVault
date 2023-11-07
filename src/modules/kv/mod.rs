use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde_json::{Value, Map};
use crate::{new_path, new_path_internal, new_logical_backend, new_logical_backend_internal};
use crate::logical::{Backend, LogicalBackend, Request, Response};
use crate::logical::{Operation, Path, PathOperation, Field, FieldType};
use crate::storage::{StorageEntry};
use crate::modules::Module;
use crate::core::Core;
use crate::errors::RvError;

static KV_BACKEND_HELP: &str = r#"
The generic backend reads and writes arbitrary secrets to the backend.
The secrets are encrypted/decrypted by RustyVault: they are never stored
unencrypted in the backend and the backend never has an opportunity to
see the unencrypted value.

Leases can be set on a per-secret basis. These leases will be sent down
when that secret is read, and it is assumed that some outside process will
revoke and/or replace the secret at that path.
"#;

pub struct KvModule {
    pub name: String,
}

pub struct KvBackend;

impl KvBackend {
    pub fn new_backend() -> LogicalBackend {
        let kv_backend = Arc::new(KvBackend);

        let kv_backend_r = Arc::clone(&kv_backend);
        let kv_backend_w = Arc::clone(&kv_backend);
        let kv_backend_d = Arc::clone(&kv_backend);
        let kv_backend_l = Arc::clone(&kv_backend);

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: ".*",
                    fields: {
                        "lease": {
                            field_type: FieldType::Str,
                            default: "",
                            description: "Lease time for this key when read. Ex: 1h"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: kv_backend_r.handle_read},
                        {op: Operation::Write, handler: kv_backend_w.handle_write},
                        {op: Operation::Delete, handler: kv_backend_d.handle_delete},
                        {op: Operation::List, handler: kv_backend_l.handle_list}
                    ],
                    help: "Pass-through secret storage to the physical backend, allowing you to read/write arbitrary data into secret storage."
                }
            ],
            help: KV_BACKEND_HELP
        });

        backend
    }

    pub fn handle_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let entry = req.storage_get(&req.path)?;
        if entry.is_none() {
            return Ok(None);
        }

        let data: Map<String, Value> = serde_json::from_slice(entry.unwrap().value.as_slice())?;

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrModuleKvDataFieldMissing);
        }

        let data = serde_json::to_string(req.body.as_ref().unwrap())?;
        let entry = StorageEntry {
            key: req.path.clone(),
            value: data.into_bytes(),
        };

        req.storage_put(&entry)?;
        Ok(None)
    }

    pub fn handle_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        req.storage_delete(&req.path)?;
        Ok(None)
    }

    pub fn handle_list(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let keys = req.storage_list(&req.path)?;
        let resp = Response::list_response(&keys);
        Ok(Some(resp))
    }
}

impl KvModule {
    pub fn new() -> Self {
        Self {
            name: "kv".to_string(),
        }
    }
}

impl Module for KvModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn init(&self, core: &Core) -> Result<(), RvError> {
        let kv_backend_new_func = |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut kv_backend = KvBackend::new_backend();
            kv_backend.init()?;
            Ok(Arc::new(kv_backend))
        };
        core.add_logical_backend("kv", Arc::new(kv_backend_new_func))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.remove_logical_backend("kv")
    }
}
