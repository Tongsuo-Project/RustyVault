use std::rc::Rc;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use serde_json::{json, from_value, Value, Map};
use crate::{new_path, new_path_internal, new_logical_backend, new_logical_backend_internal};
use crate::logical::{Backend, LogicalBackend, Request, Response};
use crate::logical::{Operation, Path, PathOperation, Field, FieldType};
use crate::storage::{StorageEntry};
use crate::modules::Module;
use crate::mount::MountEntry;
use crate::core::Core;
use crate::errors::RvError;

static SYSTEM_BACKEND_HELP: &str = r#"
The system backend is built-in to RustyVault and cannot be remounted or
unmounted. It contains the paths that are used to configure RustyVault itself
as well as perform core operations.
"#;

pub struct SystemModule {
    pub name: String,
}

pub struct SystemBackend {
    pub core: Arc<RwLock<Box<Core>>>,
}

impl SystemBackend {
    pub fn new_backend(core: Arc<RwLock<Box<Core>>>) -> LogicalBackend {
        let sys_backend = Rc::new(
            SystemBackend {
                core: core,
            }
        );

        let sys_backend_mount_table = Rc::clone(&sys_backend);
        let sys_backend_mount_write = Rc::clone(&sys_backend);
        let sys_backend_mount_delete = Rc::clone(&sys_backend);
        let sys_backend_remount = Rc::clone(&sys_backend);
        let sys_backend_renew = Rc::clone(&sys_backend);
        let sys_backend_revoke = Rc::clone(&sys_backend);
        let sys_backend_revoke_prefix = Rc::clone(&sys_backend);
        let sys_backend_auth_table = Rc::clone(&sys_backend);
        let sys_backend_auth_enable = Rc::clone(&sys_backend);
        let sys_backend_auth_disable = Rc::clone(&sys_backend);
        let sys_backend_policy_list = Rc::clone(&sys_backend);
        let sys_backend_policy_read = Rc::clone(&sys_backend);
        let sys_backend_policy_write = Rc::clone(&sys_backend);
        let sys_backend_policy_delete = Rc::clone(&sys_backend);
        let sys_backend_audit_table = Rc::clone(&sys_backend);
        let sys_backend_audit_enable = Rc::clone(&sys_backend);
        let sys_backend_audit_disable = Rc::clone(&sys_backend);
        let sys_backend_raw_read = Rc::clone(&sys_backend);
        let sys_backend_raw_write = Rc::clone(&sys_backend);
        let sys_backend_raw_delete = Rc::clone(&sys_backend);

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
                            description: r#"User-friendly description for this mount."#
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
                            description: r#"User-friendly description for this crential backend."#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: sys_backend_auth_enable.handle_auth_enable},
                        {op: Operation::Delete, handler: sys_backend_auth_disable.handle_auth_disable}
                    ]
                },
                {
                    pattern: "policy$",
                    operations: [
                        {op: Operation::Read, handler: sys_backend_policy_list.handle_policy_list}
                    ]
                },
                {
                    pattern: "policy/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: r#"The name of the policy. Example: "ops""#
                        },
                        "rules": {
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
            help: SYSTEM_BACKEND_HELP
        });

        backend
    }

    pub fn handle_mount_table(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        let core = self.core.read()?;
        if core.mounts.is_none() {
            return Err(RvError::ErrMountTableNotReady);
        }

        let mut data: Map<String, Value> = Map::new();

        let mounts_ref = core.mounts.as_ref().unwrap();
        let mounts = mounts_ref.entries.read()?;

        for entry in mounts.values() {
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
        let description = req.get_data("description")?;

        let path = path.as_str().unwrap();
        let logical_type = logical_type.as_str().unwrap();
        let description = description.as_str().unwrap();

        if logical_type == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        let me = MountEntry::new(path, logical_type, description);
        let core = self.core.read()?;
        core.mount(&me)?;
        Ok(None)
    }

    pub fn handle_unmount(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let suffix = req.path.strip_prefix("mounts/");
        if suffix.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let core = self.core.read()?;
        core.unmount(suffix.unwrap())?;
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

        let core = self.core.read()?;
        core.remount(from, to)?;
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
        Ok(None)
    }

    pub fn handle_auth_enable(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        /*
        let path: String = to_string(&req.get_data("path")?)?;
        let logical_type: String = to_string(&req.get_data("type")?)?;
        let description: String = to_string(&req.get_data("description")?)?;
        if logical_type == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        let me = MountEntry::new(&path, &logical_type, &description);
        let core = self.core.read()?;
        core.mount(&me)?;
        */
        Ok(None)
    }

    pub fn handle_auth_disable(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_policy_list(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_policy_read(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_policy_write(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_policy_delete(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_audit_table(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_audit_enable(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_audit_disable(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn handle_raw_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        let core = self.core.read()?;
        let storage = core.barrier.as_storage();
        let entry = storage.get(path)?;
        if entry.is_none() {
            return Ok(None);
        }

        let data = json!({
            "value": String::from_utf8_lossy(&entry.unwrap().value),
        }).as_object().unwrap().clone();

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_raw_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;
        let value = req.get_data("value")?;

        let path = path.as_str().unwrap();
        let value = value.as_str().unwrap();

        let core = self.core.read()?;
        let storage = core.barrier.as_storage();

        let entry = StorageEntry {
            key: path.to_string(),
            value: value.as_bytes().to_vec(),
        };

        storage.put(&entry)?;

        Ok(None)
    }

    pub fn handle_raw_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let path = req.get_data("path")?;

        let path = path.as_str().unwrap();

        let core = self.core.read()?;
        let storage = core.barrier.as_storage();

        storage.delete(path)?;

        Ok(None)
    }
}

impl SystemModule {
    pub fn new() -> Self {
        Self {
            name: "system".to_string(),
        }
    }
}

impl Module for SystemModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn init(&self, core: &Core) -> Result<(), RvError> {
        let sys_backend_new_func = |c: Arc<RwLock<Box<Core>>>| -> Result<Box<dyn Backend>, RvError> {
            let mut sys_backend = SystemBackend::new_backend(c);
            sys_backend.init()?;
            Ok(Box::new(sys_backend))
        };
        core.add_logical_backend("system", Arc::new(Box::new(sys_backend_new_func)))
    }

    fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        core.remove_logical_backend("system")
    }
}
