//! The system module is mainly used to configure RustyVault itself. For instance, the 'mount/'
//! path is provided here to support mounting new modules in RustyVault via RESTful HTTP request.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use as_any::Downcast;
use derive_more::Deref;
use serde_json::{from_value, json, Map, Value};

use crate::{
    context::Context,
    core::Core,
    errors::RvError,
    logical::{
        field::FieldTrait, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    modules::{
        auth::{AuthModule, AUTH_TABLE_TYPE},
        policy::PolicyModule,
        Module,
    },
    mount::{MountEntry, MOUNT_TABLE_TYPE},
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    rv_error_response_status,
    storage::StorageEntry,
};

static SYSTEM_BACKEND_HELP: &str = r#"
The system backend is built-in to RustyVault and cannot be remounted or
unmounted. It contains the paths that are used to configure RustyVault itself
as well as perform core operations.
"#;

pub struct SystemModule {
    pub name: String,
    pub backend: Arc<SystemBackend>,
}

pub struct SystemBackendInner {
    pub core: Arc<RwLock<Core>>,
}

#[derive(Deref)]
pub struct SystemBackend {
    #[deref]
    pub inner: Arc<SystemBackendInner>,
}

impl SystemBackend {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { inner: Arc::new(SystemBackendInner { core }) }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let sys_backend_mount_table = Arc::clone(&self.inner);
        let sys_backend_mount_write = Arc::clone(&self.inner);
        let sys_backend_mount_delete = Arc::clone(&self.inner);
        let sys_backend_remount = Arc::clone(&self.inner);
        let sys_backend_renew = Arc::clone(&self.inner);
        let sys_backend_revoke = Arc::clone(&self.inner);
        let sys_backend_revoke_prefix = Arc::clone(&self.inner);
        let sys_backend_auth_table = Arc::clone(&self.inner);
        let sys_backend_auth_enable = Arc::clone(&self.inner);
        let sys_backend_auth_disable = Arc::clone(&self.inner);
        let sys_backend_policy_list1 = Arc::clone(&self.inner);
        let sys_backend_policy_list2 = Arc::clone(&self.inner);
        let sys_backend_policy_read = Arc::clone(&self.inner);
        let sys_backend_policy_write = Arc::clone(&self.inner);
        let sys_backend_policy_delete = Arc::clone(&self.inner);
        let sys_backend_audit_table = Arc::clone(&self.inner);
        let sys_backend_audit_enable = Arc::clone(&self.inner);
        let sys_backend_audit_disable = Arc::clone(&self.inner);
        let sys_backend_raw_read = Arc::clone(&self.inner);
        let sys_backend_raw_write = Arc::clone(&self.inner);
        let sys_backend_raw_delete = Arc::clone(&self.inner);

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "mounts$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_mount_table.handle_mount_table}
                    ]
                },
                {
                    pattern: "mounts/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The path to mount to. Example: "aws/east""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "kv""#
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: r#"User-friendly description for this mount."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            required: false,
                            description: r#"The options to pass into the backend. Should be a json object with string keys and values."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_mount_write.handle_mount},
                        {op: Operation::Delete, handler: sys_backend_mount_delete.handle_unmount}
                    ]
                },
                {
                    pattern: "remount",
                    fields: {
                        "from": {
                            field_type: FieldType::Str
                        },
                        "to": {
                            field_type: FieldType::Str
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_remount.handle_remount}
                    ]
                },
                {
                    pattern: "renew/(?P<lease_id>.+)",
                    fields: {
                        "lease_id": {
                            field_type: FieldType::Str,
                            description: "The lease identifier to renew. This is included with a lease."
                        },
                        "increment": {
                            field_type: FieldType::Int,
                            description: "The desired increment in seconds to the lease"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_renew.handle_renew}
                    ]
                },
                {
                    pattern: "revoke/(?P<lease_id>.+)",
                    fields: {
                        "lease_id": {
                            field_type: FieldType::Str,
                            description: "The lease identifier to renew. This is included with a lease."
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_revoke.handle_revoke}
                    ]
                },
                {
                    pattern: "revoke-prefix/(?P<prefix>.+)",
                    fields: {
                        "prefix": {
                            field_type: FieldType::Str,
                            description: r#"The path to revoke keys under. Example: "prod/aws/ops""#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_revoke_prefix.handle_revoke_prefix}
                    ]
                },
                {
                    pattern: "auth$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_auth_table.handle_auth_table}
                    ]
                },
                {
                    pattern: "auth/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The path to mount to. Cannot be delimited. Example: "user""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "userpass""#
                        },
                        "description": {
                            field_type: FieldType::Str,
                            default: "",
                            description: r#"User-friendly description for this crential backend."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            required: false,
                            description: r#"The options to pass into the backend. Should be a json object with string keys and values."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_auth_enable.handle_auth_enable},
                        {op: Operation::Delete, handler: sys_backend_auth_disable.handle_auth_disable}
                    ]
                },
                {
                    pattern: "policy/?$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_list1.handle_policy_list},
                        {op: Operation::List, handler: sys_backend_policy_list2.handle_policy_list}
                    ]
                },
                {
                    pattern: "policy/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy. Example: "ops""#
                        },
                        "policy": {
                            field_type: FieldType::Str,
                            description: r#"The rules of the policy. Either given in HCL or JSON format."#
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_read.handle_policy_read},
                        {op: Operation::Write, handler: sys_backend_policy_write.handle_policy_write},
                        {op: Operation::Delete, handler: sys_backend_policy_delete.handle_policy_delete}
                    ]
                },
                {
                    pattern: "audit$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_audit_table.handle_audit_table}
                    ]
                },
                {
                    pattern: "audit/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str,
                            description: r#"The name of the backend. Cannot be delimited. Example: "mysql""#
                        },
                        "type": {
                            field_type: FieldType::Str,
                            description: r#"The type of the backend. Example: "mysql""#
                        },
                        "description": {
                            required: false,
                            field_type: FieldType::Str,
                            description: r#"User-friendly description for this audit backend."#
                        },
                        "options": {
                            field_type: FieldType::Map,
                            description: r#"Configuration options for the audit backend."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_audit_enable.handle_audit_enable},
                        {op: Operation::Delete, handler: sys_backend_audit_disable.handle_audit_disable}
                    ]
                },
                {
                    pattern: "raw/(?P<path>.+)",
                    fields: {
                        "path": {
                            field_type: FieldType::Str
                        },
                        "value": {
                            field_type: FieldType::Str
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: sys_backend_raw_read.handle_raw_read},
                        {op: Operation::Write, handler: sys_backend_raw_write.handle_raw_write},
                        {op: Operation::Delete, handler: sys_backend_raw_delete.handle_raw_delete}
                    ]
                }
            ],
            root_paths: ["mounts/*", "auth/*", "remount", "policy", "policy/*", "audit", "audit/*", "seal", "raw/*", "revoke-prefix/*"],
            help: SYSTEM_BACKEND_HELP,
        });

        backend
    }
}

impl SystemBackendInner {
    pub fn handle_mount_table(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        let core = self.core.read()?;
        let mut data: Map<String, Value> = Map::new();

        let mounts = core.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let info: Value = json!({
                "type": entry.logical_type.clone(),
                "description": entry.description.clone(),
            });
            data.insert(entry.path.clone(), info);
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_mount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let logical_type = req.get_data("type")?;
        let description = req.get_data_or_default("description")?;
        let options = req.get_data_or_default("options")?;

        let path = path.as_str().unwrap();
        let logical_type = logical_type.as_str().unwrap();
        let description = description.as_str().unwrap();

        if logical_type.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut me = MountEntry::new(&MOUNT_TABLE_TYPE, path, logical_type, description);
        me.options = options.as_map();

        let core = self.core.read()?;
        core.mount(&me)?;
        Ok(None)
    }

    pub fn handle_unmount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let suffix = req.path.trim_start_matches("mounts/");
        if suffix.len() == 0 {
            return Err(RvError::ErrRequestInvalid);
        }

        let core = self.core.read()?;
        core.unmount(&suffix)?;
        Ok(None)
    }

    pub fn handle_remount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let from = req.get_data("from")?;
        let to = req.get_data("to")?;

        let from = from.as_str().unwrap();
        let to = to.as_str().unwrap();
        if from.len() == 0 || to.len() == 0 {
            return Err(RvError::ErrRequestInvalid);
        }

        let from_path = sanitize_path(from);
        let to_path = sanitize_path(to);
        let core = self.core.read()?;

        if let Some(me) = core.router.matching_mount_entry(&from_path)? {
            let mount_entry = me.read()?;

            let dst_path_match = core.router.matching_mount(&to)?;
            if dst_path_match.len() != 0 {
                return Err(rv_error_response_status!(409, &format!("path already in use at {}", dst_path_match)));
            }

            let mount_entry_table_type = mount_entry.table.clone();

            std::mem::drop(mount_entry);

            match mount_entry_table_type.as_str() {
                AUTH_TABLE_TYPE => {
                    let module = self.get_auth_module()?;
                    let auth_mod = module.read()?;
                    let auth_module =
                        auth_mod.as_ref().downcast_ref::<AuthModule>().ok_or(RvError::ErrRustDowncastFailed)?;
                    auth_module.remount_auth(&from_path, &to_path)?;
                }
                MOUNT_TABLE_TYPE => {
                    core.remount(&from_path, &to_path)?;
                }
                _ => {
                    return Err(rv_error_response_status!(409, "Unknown mount table type."));
                }
            }
        } else {
            return Err(rv_error_response_status!(409, &format!("no matching mount at {}", from_path)));
        }

        Ok(None)
    }

    pub fn handle_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let _lease_id = req.get_data("lease_id")?;
        let _increment: i32 = from_value(req.get_data("increment")?)?;
        //TODO
        Ok(None)
    }

    pub fn handle_revoke(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let _lease_id = req.get_data("lease_id")?;
        //TODO
        Ok(None)
    }

    pub fn handle_revoke_prefix(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let _prefix = req.get_data("prefix")?;
        Ok(None)
    }

    pub fn handle_auth_table(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut data: Map<String, Value> = Map::new();

        let module = self.get_auth_module()?;
        let auth_mod = module.read()?;
        let auth_module = auth_mod.as_ref().downcast_ref::<AuthModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        let router_store = auth_module.router_store.read()?;
        let mounts = router_store.mounts.entries.read()?;

        for mount_entry in mounts.values() {
            let entry = mount_entry.read()?;
            let info: Value = json!({
                "type": entry.logical_type.clone(),
                "description": entry.description.clone(),
            });
            data.insert(entry.path.clone(), info);
        }

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_auth_enable(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let logical_type = req.get_data("type")?;
        let description = req.get_data_or_default("description")?;
        let options = req.get_data_or_default("options")?;

        let path = sanitize_path(path.as_str().unwrap());
        let logical_type = logical_type.as_str().unwrap();
        let description = description.as_str().unwrap();

        if logical_type.is_empty() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut me = MountEntry::new(&AUTH_TABLE_TYPE, &path, logical_type, description);

        me.options = options.as_map();

        let module = self.get_auth_module()?;
        let auth_mod = module.read()?;
        let auth_module = auth_mod.as_ref().downcast_ref::<AuthModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        auth_module.enable_auth(&me)?;

        Ok(None)
    }

    pub fn handle_auth_disable(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = sanitize_path(req.path.trim_start_matches("auth/"));
        if path.len() == 0 {
            return Err(RvError::ErrRequestInvalid);
        }

        let module = self.get_auth_module()?;
        let auth_mod = module.read()?;
        let auth_module = auth_mod.as_ref().downcast_ref::<AuthModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        auth_module.disable_auth(&path)?;

        Ok(None)
    }

    pub fn handle_policy_list(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let module = self.get_policy_module()?;
        let policy_mod = module.read()?;
        let policy_module = policy_mod.as_ref().downcast_ref::<PolicyModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        policy_module.handle_policy_list(backend, req)
    }

    pub fn handle_policy_read(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let module = self.get_policy_module()?;
        let policy_mod = module.read()?;
        let policy_module = policy_mod.as_ref().downcast_ref::<PolicyModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        policy_module.handle_policy_read(backend, req)
    }

    pub fn handle_policy_write(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let module = self.get_policy_module()?;
        let policy_mod = module.read()?;
        let policy_module = policy_mod.as_ref().downcast_ref::<PolicyModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        policy_module.handle_policy_write(backend, req)
    }

    pub fn handle_policy_delete(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let module = self.get_policy_module()?;
        let policy_mod = module.read()?;
        let policy_module = policy_mod.as_ref().downcast_ref::<PolicyModule>().ok_or(RvError::ErrRustDowncastFailed)?;

        policy_module.handle_policy_delete(backend, req)
    }

    pub fn handle_audit_table(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_audit_enable(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_audit_disable(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_raw_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        let core = self.core.read()?;
        let entry = core.barrier.get(path)?;
        if entry.is_none() {
            return Ok(None);
        }

        let data = json!({
            "value": String::from_utf8_lossy(&entry.unwrap().value),
        })
        .as_object()
        .unwrap()
        .clone();

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_raw_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let value = req.get_data("value")?;

        let path = path.as_str().unwrap();
        let value = value.as_str().unwrap();

        let core = self.core.read()?;

        let entry = StorageEntry { key: path.to_string(), value: value.as_bytes().to_vec() };

        core.barrier.put(&entry)?;

        Ok(None)
    }

    pub fn handle_raw_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        let core = self.core.read()?;

        core.barrier.delete(path)?;

        Ok(None)
    }

    fn get_module(&self, name: &str) -> Result<Arc<RwLock<Box<dyn Module>>>, RvError> {
        let core = self.core.read().unwrap();
        if let Some(module) = core.module_manager.get_module(name) {
            return Ok(module);
        }

        Err(RvError::ErrModuleNotFound)
    }

    fn get_auth_module(&self) -> Result<Arc<RwLock<Box<dyn Module>>>, RvError> {
        self.get_module("auth")
    }

    fn get_policy_module(&self) -> Result<Arc<RwLock<Box<dyn Module>>>, RvError> {
        self.get_module("policy")
    }
}

impl SystemModule {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self { name: "system".to_string(), backend: Arc::new(SystemBackend::new(core)) }
    }
}

impl Module for SystemModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let sys = Arc::clone(&self.backend);
        let sys_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut sys_backend = sys.new_backend();
            sys_backend.init()?;
            Ok(Arc::new(sys_backend))
        };
        core.add_logical_backend("system", Arc::new(sys_backend_new_func))
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("system")
    }
}

fn sanitize_path(path: &str) -> String {
    let mut new_path = path.to_string();
    if !new_path.ends_with('/') {
        new_path.push('/');
    }
    if new_path.starts_with('/') {
        new_path = new_path[1..].to_string();
    }
    new_path
}
