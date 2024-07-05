//! The secure key-value object storage module. The user can use this module to store arbitary data
//! into RustyVault. The data stored in RustyVault is encrypted.

use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, RwLock},
    time::Duration,
};

use humantime::parse_duration;
use serde_json::{Map, Value};

use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    modules::Module,
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    new_secret, new_secret_internal,
    storage::StorageEntry,
};

static KV_BACKEND_HELP: &str = r#"
The generic backend reads and writes arbitrary secrets to the backend.
The secrets are encrypted/decrypted by RustyVault: they are never stored
unencrypted in the backend and the backend never has an opportunity to
see the unencrypted value.

Leases can be set on a per-secret basis. These leases will be sent down
when that secret is read, and it is assumed that some outside process will
revoke and/or replace the secret at that path.
"#;
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(3600 as u64);

pub struct KvModule {
    pub name: String,
    pub backend: Arc<KvBackend>,
}

pub struct KvBackendInner {
    pub core: Arc<RwLock<Core>>,
}

pub struct KvBackend {
    pub inner: Arc<KvBackendInner>,
}

impl Deref for KvBackend {
    type Target = KvBackendInner;

    fn deref(&self) -> &KvBackendInner {
        &self.inner
    }
}

impl KvBackend {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { inner: Arc::new(KvBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let kv_backend_read = Arc::clone(&self.inner);
        let kv_backend_write = Arc::clone(&self.inner);
        let kv_backend_delete = Arc::clone(&self.inner);
        let kv_backend_list = Arc::clone(&self.inner);
        let kv_backend_renew = Arc::clone(&self.inner);
        let kv_backend_revoke = Arc::clone(&self.inner);

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: ".*",
                    fields: {
                        "ttl": {
                            field_type: FieldType::Int,
                            default: "",
                            description: "Lease time for this key when read. Ex: 1h"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: kv_backend_read.handle_read},
                        {op: Operation::Write, handler: kv_backend_write.handle_write},
                        {op: Operation::Delete, handler: kv_backend_delete.handle_delete},
                        {op: Operation::List, handler: kv_backend_list.handle_list}
                    ],
                    help: "Pass-through secret storage to the physical backend, allowing you to read/write arbitrary data into secret storage."
                }
            ],
            secrets: [{
                secret_type: "kv",
                renew_handler: kv_backend_renew.handle_read,
                revoke_handler: kv_backend_revoke.handle_noop,
            }],
            help: KV_BACKEND_HELP,
        });

        backend
    }
}

impl KvBackendInner {
    pub fn handle_read(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let entry = req.storage_get(&req.path)?;
        if entry.is_none() {
            return Ok(None);
        }

        let mut ttl_duration: Option<Duration> = None;
        let data: Map<String, Value> = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        if let Some(ttl) = data.get("ttl") {
            if let Some(ttl_i64) = ttl.as_i64() {
                ttl_duration = Some(Duration::from_secs(ttl_i64 as u64));
            } else if let Some(ttl_str) = ttl.as_str() {
                if let Ok(ttl_dur) = parse_duration(ttl_str) {
                    ttl_duration = Some(ttl_dur);
                }
            }
        } else {
            if let Some(lease) = data.get("lease") {
                if let Some(lease_i64) = lease.as_i64() {
                    ttl_duration = Some(Duration::from_secs(lease_i64 as u64));
                } else if let Some(lease_str) = lease.as_str() {
                    if let Ok(lease_dur) = parse_duration(lease_str) {
                        ttl_duration = Some(lease_dur);
                    }
                }
            }
        }

        let mut resp = backend.secret("kv").unwrap().response(Some(data), None);
        let secret = resp.secret.as_mut().unwrap();
        secret.lease.renewable = false;
        if let Some(ttl) = ttl_duration {
            secret.lease.ttl = ttl;
            secret.lease.renewable = true;
        } else {
            secret.lease.ttl = DEFAULT_LEASE_TTL;
        }

        Ok(Some(resp))
    }

    pub fn handle_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrModuleKvDataFieldMissing);
        }

        let data = serde_json::to_string(req.body.as_ref().unwrap())?;
        let entry = StorageEntry { key: req.path.clone(), value: data.into_bytes() };

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

    pub fn handle_noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl KvModule {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { name: "kv".to_string(), backend: Arc::new(KvBackend::new(core)) }
    }
}

impl Module for KvModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let kv = Arc::clone(&self.backend);
        let kv_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut kv_backend = kv.new_backend();
            kv_backend.init()?;
            Ok(Arc::new(kv_backend))
        };
        core.add_logical_backend("kv", Arc::new(kv_backend_new_func))
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("kv")
    }
}
