use std::{collections::HashMap, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    context::Context, errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
    utils::{deserialize_duration, serialize_duration},
};

//const DEFAULT_MAX_TTL: Duration = Duration::from_secs(365*24*60*60 as u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    pub password_hash: String,
    pub policies: Vec<String>,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_ttl: Duration,
}

impl Default for UserEntry {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            policies: Vec::new(),
            ttl: Duration::from_secs(0),
            max_ttl: Duration::from_secs(0),
        }
    }
}

impl UserPassBackend {
    pub fn users_path(&self) -> Path {
        let userpass_backend_ref1 = Arc::clone(&self.inner);
        let userpass_backend_ref2 = Arc::clone(&self.inner);
        let userpass_backend_ref3 = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"users/(?P<username>\w[\w-]+\w)",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username of the user."
                },
                "password": {
                    field_type: FieldType::SecretStr,
                    required: false,
                    description: "Password for this user."
                },
                "policies": {
                    field_type: FieldType::Str,
                    required: false,
                    description: "Policies for this user."
                },
                "ttl": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "TTL for this user."
                },
                "max_ttl": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "TTL for this user."
                }
            },
            operations: [
                {op: Operation::Read, handler: userpass_backend_ref1.read_user},
                {op: Operation::Write, handler: userpass_backend_ref2.write_user},
                {op: Operation::Delete, handler: userpass_backend_ref3.delete_user}
            ],
            help: r#"
This endpoint allows you to create, read, update, and delete users
that are allowed to authenticate.
Deleting a user will not revoke auth for prior authenticated users
with that name. To do this, do a revoke on "login/<username>" for
the username you want revoked. If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
                "#
        });

        path
    }

    pub fn user_list_path(&self) -> Path {
        let userpass_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"users/?",
            operations: [
                {op: Operation::List, handler: userpass_backend_ref.list_user}
            ],
            help: r#"This endpoint allows you to list users"#
        });

        path
    }

    pub fn user_password_path(&self) -> Path {
        let userpass_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"users/(?P<username>\w[\w-]+\w)/password$",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username of the user."
                },
                "password": {
                    field_type: FieldType::SecretStr,
                    required: true,
                    description: "Password for this user."
                }
            },
            operations: [
                {op: Operation::Write, handler: userpass_backend_ref.write_user_password}
            ],
            help: r#"This endpoint allows resetting the user's password."#
        });

        path
    }
}

impl UserPassBackendInner {
    pub fn get_user(&self, req: &mut Request, name: &str) -> Result<Option<UserEntry>, RvError> {
        let key = format!("user/{}", name.to_lowercase());
        let storage_entry = req.storage_get(&key)?;
        if storage_entry.is_none() {
            return Ok(None);
        }

        let entry = storage_entry.unwrap();
        let user_entry: UserEntry = serde_json::from_slice(entry.value.as_slice())?;
        Ok(Some(user_entry))
    }

    pub fn set_user(&self, req: &mut Request, name: &str, user_entry: &UserEntry) -> Result<(), RvError> {
        let entry = StorageEntry::new(format!("user/{}", name).as_str(), user_entry)?;

        req.storage_put(&entry)
    }

    pub fn read_user(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_lowercase();

        let entry = self.get_user(req, &username)?;
        if entry.is_none() {
            return Ok(None);
        }

        let user_entry = entry.unwrap();
        let mut user_entry_data = serde_json::to_value(&user_entry)?;
        let data = user_entry_data.as_object_mut().unwrap();
        data.remove("password_hash");
        Ok(Some(Response::data_response(Some(data.clone()))))
    }

    pub fn write_user(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_lowercase();

        let mut user_entry = UserEntry::default();

        if let Some(entry) = self.get_user(req, &username)? {
            user_entry = entry;
        }

        if let Ok(password_value) = req.get_data("password") {
            let password = password_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;
            if password != "" {
                user_entry.password_hash = self.gen_password_hash(password)?;
            }
        }

        let ttl_value = req.get_data_or_default("ttl")?;
        let ttl = ttl_value.as_u64().ok_or(RvError::ErrRequestFieldInvalid)?;
        if ttl > 0 {
            user_entry.ttl = Duration::from_secs(ttl);
        }

        let max_ttl_value = req.get_data_or_default("max_ttl")?;
        let max_ttl = max_ttl_value.as_u64().ok_or(RvError::ErrRequestFieldInvalid)?;
        if max_ttl > 0 {
            user_entry.max_ttl = Duration::from_secs(max_ttl);
        }

        self.set_user(req, &username, &user_entry)?;

        Ok(None)
    }

    pub fn delete_user(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;
        if username == "" {
            return Err(RvError::ErrRequestNoDataField);
        }

        req.storage_delete(format!("user/{}", username.to_lowercase()).as_str())?;
        Ok(None)
    }

    pub fn list_user(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let users = req.storage_list("user/")?;
        let resp = Response::list_response(&users);
        Ok(Some(resp))
    }

    pub fn write_user_password(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;

        let mut user_entry = UserEntry::default();

        let entry = self.get_user(req, username)?;
        if entry.is_some() {
            user_entry = entry.unwrap();
        }

        let password_value = req.get_data("password")?;
        let password = password_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;

        let password_hash = self.gen_password_hash(password)?;

        user_entry.password_hash = password_hash;

        self.set_user(req, username, &user_entry)?;

        Ok(None)
    }

    pub fn gen_password_hash(&self, password: &str) -> Result<String, RvError> {
        let pwd_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
        Ok(pwd_hash)
    }

    pub fn verify_password_hash(&self, password: &str, password_hash: &str) -> Result<bool, RvError> {
        let result = bcrypt::verify(password, password_hash)?;
        Ok(result)
    }
}
