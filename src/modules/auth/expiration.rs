//! This file contains the implementation of the ExpirationManager, which is responsible
//! for managing lease entries and their expiration. It includes functionalities to register,
//! renew, and revoke leases, as well as to check for expired leases and handle them accordingly.

use std::{
    cmp::Reverse,
    collections::HashMap,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::{Arc, RwLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use better_default::Default;
use delay_timer::prelude::{DelayTimer, DelayTimerBuilder, TaskBuilder};
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::TokenStore;
use crate::{
    core::Core,
    errors::RvError,
    logical::{lease::calculate_ttl, Auth, Request, Response, SecretData},
    router::Router,
    storage::{barrier_view::BarrierView, Storage, StorageEntry},
    utils::{
        deserialize_system_time, generate_uuid, serialize_system_time,
        token_util::{DEFAULT_LEASE_TTL, MAX_LEASE_TTL},
    },
};

pub const EXPIRATION_SUB_PATH: &str = "expire/";
pub const LEASE_VIEW_PREFIX: &str = "id/";
pub const TOKEN_VIEW_PREFIX: &str = "token/";
pub const MAX_REVOKE_ATTEMPTS: u32 = 6;
pub const REVOKE_RETRY_SECS: Duration = Duration::from_secs(10);
pub const MIN_REVOKE_DELAY_SECS: Duration = Duration::from_secs(5);
pub const MAX_LEASE_DURATION_SECS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_LEASE_DURATION_SECS: Duration = Duration::from_secs(24 * 60 * 60);

/// Represents an old lease entry that may need to be converted to the new format.
#[derive(Eq, Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
struct OldLeaseEntry {
    #[serde(default)]
    pub lease_id: String,
    pub client_token: String,
    pub path: String,
    pub data: Option<HashMap<String, Value>>,
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub issue_time: SystemTime,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub expire_time: SystemTime,
}

/// Represents a lease entry with all the necessary information.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct LeaseEntry {
    #[serde(default)]
    pub lease_id: String,
    pub client_token: String,
    pub path: String,
    pub data: Map<String, Value>,
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub issue_time: SystemTime,
    #[default(SystemTime::now())]
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub expire_time: SystemTime,
}

/// The ExpirationManager is responsible for managing lease entries and their expiration.
pub struct ExpirationManager {
    pub self_ptr: Weak<Self>,
    pub router: Arc<Router>,
    pub id_view: Arc<BarrierView>,
    pub token_view: Arc<BarrierView>,
    pub token_store: RwLock<Weak<TokenStore>>,
    queue: Arc<RwLock<PriorityQueue<Arc<LeaseEntry>, Reverse<u64>>>>,
    task_timer: DelayTimer,
}

impl Hash for LeaseEntry {
    /// Implements hash function for lease entries based on unique attributes.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.lease_id.hash(state);
        self.client_token.hash(state);
        self.path.hash(state);
    }
}

impl PartialEq for LeaseEntry {
    /// Implements partial equality checking for lease entries.
    fn eq(&self, other: &Self) -> bool {
        self.lease_id == other.lease_id && self.client_token == other.client_token && self.path == other.path
    }
}

impl Eq for LeaseEntry {}

impl LeaseEntry {
    /// Checks if the lease entry is renewable.
    fn renewable(&self) -> bool {
        let now = SystemTime::now();
        if self.expire_time < now {
            return false;
        }

        if self.secret.is_some() && !self.secret.as_ref().unwrap().renewable() {
            return false;
        }

        if self.auth.is_some() && !self.auth.as_ref().unwrap().renewable() {
            return false;
        }

        true
    }
}

impl ExpirationManager {
    /// Creates a new ExpirationManager instance.
    pub fn new(core: &Core) -> Result<ExpirationManager, RvError> {
        if core.system_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = core.system_view.as_ref().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
        let token_view = core.system_view.as_ref().unwrap().new_sub_view(TOKEN_VIEW_PREFIX);

        let expiration = ExpirationManager {
            self_ptr: Weak::new(),
            router: Arc::clone(&core.router),
            id_view: Arc::new(id_view),
            token_view: Arc::new(token_view),
            token_store: RwLock::new(Weak::new()),
            queue: Arc::new(RwLock::new(PriorityQueue::new())),
            task_timer: DelayTimerBuilder::default().build(),
        };

        Ok(expiration)
    }

    /// Wraps the ExpirationManager in an Arc and sets the weak pointer.
    pub fn wrap(self) -> Arc<Self> {
        let mut wrap_self = Arc::new(self);
        let weak_self = Arc::downgrade(&wrap_self);
        unsafe {
            let ptr_self = Arc::into_raw(wrap_self) as *mut Self;
            (*ptr_self).self_ptr = weak_self;
            wrap_self = Arc::from_raw(ptr_self);
        }

        wrap_self
    }

    /// Sets the token store for the ExpirationManager.
    pub fn set_token_store(&self, ts: &Arc<TokenStore>) -> Result<(), RvError> {
        let mut token_store = self.token_store.write()?;
        *token_store = Arc::downgrade(ts);
        Ok(())
    }

    /// Restores the lease entries from the storage.
    pub fn restore(&self) -> Result<(), RvError> {
        let existing = self.id_view.get_keys()?;

        for lease_id in existing {
            let le = self.load_lease_entry(&lease_id)?;
            if le.is_none() {
                continue;
            }

            self.register_lease_entry(Arc::new(le.unwrap()))?;
        }

        Ok(())
    }

    /// Renews a lease entry by the given increment.
    pub fn renew(&self, lease_id: &str, increment: Duration) -> Result<Option<Response>, RvError> {
        let le = self.load_lease_entry(&lease_id)?;
        if le.is_none() {
            return Err(RvError::ErrLeaseNotFound);
        }

        let mut le = le.unwrap();

        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }

        let resp = self.renew_secret_lease_entry(&le, increment)?;
        if resp.is_none() {
            return Ok(None);
        }

        let mut resp = resp.unwrap();
        if resp.secret.is_none() || !resp.secret.as_ref().unwrap().enabled() {
            return Ok(Some(resp));
        }

        if let Some(secret) = resp.secret.as_mut() {
            secret.ttl = calculate_ttl(
                MAX_LEASE_TTL,
                DEFAULT_LEASE_TTL,
                increment,
                Duration::ZERO,
                secret.ttl,
                secret.max_ttl,
                Duration::ZERO,
                le.issue_time,
            )?;
            secret.lease_id = lease_id.into();
        }

        le.data = resp.data.as_ref().map(|data| data.clone()).unwrap_or(Map::new());
        le.expire_time = resp.secret.as_ref().unwrap().expiration_time();
        le.secret = resp.secret.clone();

        self.persist_lease_entry(&le)?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(Some(resp))
    }

    /// Renews a token by the given increment.
    pub fn renew_token(&self, source: &str, token: &str, increment: Duration) -> Result<Option<Auth>, RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let src = PathBuf::from(source);
        let lease_id = src.join(token_store.salt_id(token)).to_string_lossy().to_string();

        let le = self.load_lease_entry(&lease_id)?;
        if le.is_none() {
            return Err(RvError::ErrLeaseNotFound);
        }

        let mut le = le.unwrap();

        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }

        let resp = self.renew_auth_lease_entry(&le, increment)?;
        if resp.is_none() {
            return Ok(None);
        }

        let resp = resp.unwrap();
        if resp.auth.is_none() {
            return Ok(None);
        }

        let mut auth = resp.auth.unwrap();
        if !auth.enabled() {
            return Ok(Some(auth));
        }

        auth.ttl = calculate_ttl(
            MAX_LEASE_TTL,
            DEFAULT_LEASE_TTL,
            increment,
            Duration::ZERO,
            auth.ttl,
            auth.max_ttl,
            Duration::ZERO,
            le.issue_time,
        )?;
        auth.client_token = token.to_string();
        //auth.increment = Duration::from_secs(0);
        auth.issue_time = Some(SystemTime::now());

        le.expire_time = auth.expiration_time();
        le.auth = Some(auth.clone());

        self.persist_lease_entry(&le)?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(Some(auth))
    }

    /// Registers a secret from a response for lease management.
    pub fn register_secret(&self, req: &mut Request, resp: &mut Response) -> Result<(), RvError> {
        if let Some(secret) = resp.secret.as_mut() {
            if secret.ttl.as_secs() == 0 {
                secret.ttl = DEFAULT_LEASE_DURATION_SECS;
            }

            if secret.ttl > MAX_LEASE_DURATION_SECS {
                secret.ttl = MAX_LEASE_DURATION_SECS;
            }

            let now = SystemTime::now();
            secret.issue_time = Some(now);

            let path = PathBuf::from(&req.path);
            let lease_id = path.join(generate_uuid()).to_string_lossy().to_string();

            secret.lease_id = lease_id.clone();

            let le = LeaseEntry {
                lease_id,
                client_token: req.client_token.clone(),
                path: req.path.clone(),
                data: resp.data.as_ref().map(|data| data.clone()).unwrap_or(Map::new()),
                secret: Some(secret.clone()),
                issue_time: now,
                expire_time: secret.expiration_time(),
                ..Default::default()
            };

            self.persist_lease_entry(&le)?;
            self.index_by_token(&le.client_token, &le.lease_id)?;

            secret.ttl = le.expire_time.duration_since(now)?;

            self.register_lease_entry(Arc::new(le))?;
        }

        Ok(())
    }

    /// Registers an authentication lease entry.
    pub fn register_auth(&self, source: &str, auth: &mut Auth) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let src = PathBuf::from(source);
        let lease_id = src.join(token_store.salt_id(&auth.client_token)).to_string_lossy().to_string();

        let now = SystemTime::now();
        auth.issue_time = Some(now);

        let le = LeaseEntry {
            lease_id,
            client_token: auth.client_token.clone(),
            path: source.to_string(),
            auth: Some(auth.clone()),
            issue_time: now,
            expire_time: auth.expiration_time(),
            ..Default::default()
        };

        self.persist_lease_entry(&le)?;
        self.register_lease_entry(Arc::new(le))?;

        Ok(())
    }

    /// Revokes a lease entry by its lease ID.
    pub fn revoke_lease_id(&self, lease_id: &str) -> Result<(), RvError> {
        let le = self.load_lease_entry(lease_id)?;
        if le.is_none() {
            return Ok(());
        }

        let le = le.unwrap();

        log::debug!("revoke lease_id: {}", &le.lease_id);

        self.revoke_lease_entry(&le)?;
        self.delete_lease_entry(lease_id)?;
        self.index_by_token(&le.client_token, &le.lease_id)?;

        Ok(())
    }

    /// Revokes all lease entries with a given prefix.
    pub fn revoke_prefix(&self, prefix: &str) -> Result<(), RvError> {
        let mut prefix = prefix.to_string();
        if !prefix.ends_with("!") {
            prefix += "/";
        }

        let sub = self.id_view.new_sub_view(&prefix);
        let existing = sub.get_keys()?;
        for suffix in existing.iter() {
            let lease_id = format!("{}{}", prefix, suffix);
            self.revoke_lease_id(&lease_id)?;
        }

        Ok(())
    }

    /// Revokes all lease entries associated with a given token.
    pub fn revoke_by_token(&self, token: &str) -> Result<(), RvError> {
        let existing = self.lookup_by_token(token)?;
        for lease_id in existing.iter() {
            self.revoke_lease_id(&lease_id)?;
        }

        Ok(())
    }

    /// Starts a background task to check for and handle expired lease entries.
    pub fn start_check_expired_lease_entries(&self) {
        let mut task_builder = TaskBuilder::default();

        let queue = Arc::clone(&self.queue);
        let expiration = Arc::clone(&self.self_ptr.upgrade().unwrap());

        let timer_check = move || {
            let queue_cloned = Arc::clone(&queue);
            let expiration_cloned = Arc::clone(&expiration);
            async move {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                let expired = {
                    let queue_locked = queue_cloned.read().unwrap();

                    queue_locked.peek().map(|(_le, Reverse(priority))| *priority < now).unwrap_or(false)
                };

                if !expired {
                    return;
                }

                let mut queue_write_locked = queue_cloned.write().unwrap();
                loop {
                    if let Some((le, Reverse(priority))) = queue_write_locked.peek() {
                        if *priority > now {
                            return;
                        }

                        if expiration_cloned.revoke_lease_id(&le.lease_id).is_err() {
                            return;
                        }
                    } else {
                        return;
                    }

                    let _le = queue_write_locked.pop();
                }
            }
        };

        let task =
            task_builder.set_task_id(2).set_frequency_repeated_by_seconds(1).spawn_async_routine(timer_check).unwrap();
        let _ = self.task_timer.add_task(task);
    }

    /// Registers a lease entry in the priority queue for expiration tracking.
    fn register_lease_entry(&self, le: Arc<LeaseEntry>) -> Result<(), RvError> {
        let priority = le.expire_time.duration_since(UNIX_EPOCH)?.as_secs();
        let mut queue_locked = self.queue.write()?;
        queue_locked.push(le, Reverse(priority));
        Ok(())
    }

    /// Loads a lease entry from storage by lease ID, updating if necessary from old to new format.
    fn load_lease_entry(&self, lease_id: &str) -> Result<Option<LeaseEntry>, RvError> {
        let raw = self.id_view.get(lease_id)?;
        if raw.is_none() {
            return Ok(None);
        }

        if let Ok(le) = serde_json::from_slice::<LeaseEntry>(raw.clone().unwrap().value.as_slice()) {
            return Ok(Some(le));
        }

        // Because the data field type of LeaseEntry has changed, it is necessary to convert OldLeaseEntry to LeaseEntry
        // and update the data in its storage.
        if let Ok(ole) = serde_json::from_slice::<OldLeaseEntry>(raw.unwrap().value.as_slice()) {
            let le = LeaseEntry {
                lease_id: ole.lease_id.clone(),
                client_token: ole.client_token.clone(),
                path: ole.path.clone(),
                data: ole.data.clone().map(|serde_map| serde_map.into_iter().collect()).unwrap_or(Map::new()),
                secret: ole.secret.clone(),
                auth: ole.auth.clone(),
                issue_time: ole.issue_time.clone(),
                expire_time: ole.expire_time.clone(),
            };
            self.persist_lease_entry(&le)?;
            return Ok(Some(le));
        }

        Ok(None)
    }

    /// Persists a lease entry to storage.
    fn persist_lease_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        let value = serde_json::to_string(&le)?;

        let entry = StorageEntry { key: le.lease_id.clone(), value: value.as_bytes().to_vec() };

        self.id_view.put(&entry)
    }

    /// Deletes a lease entry from storage.
    fn delete_lease_entry(&self, lease_id: &str) -> Result<(), RvError> {
        self.id_view.delete(lease_id)
    }

    /// Indexes a lease entry by the associated token for easy lookup.
    fn index_by_token(&self, token: &str, lease_id: &str) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));
        let entry = StorageEntry { key, value: lease_id.as_bytes().to_owned() };
        self.token_view.put(&entry)
    }

    /// Looks up lease entries associated with a specific token.
    fn lookup_by_token(&self, token: &str) -> Result<Vec<String>, RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;
        let prefix = format!("{}/", token_store.salt_id(token));
        let sub_keys = self.token_view.list(&prefix)?;

        let mut ret: Vec<String> = Vec::new();

        for sub in sub_keys.iter() {
            let key = format!("{}{}", prefix, sub);
            let raw = self.token_view.get(&key)?;
            if raw.is_none() {
                continue;
            }

            let lease_id = String::from_utf8_lossy(&raw.unwrap().value).to_string();
            ret.push(lease_id);
        }

        Ok(ret)
    }

    /// Revokes a lease entry and handles secret or token revocation.
    fn revoke_lease_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        let token_store = self.token_store.read()?.upgrade().ok_or(RvError::ErrBarrierSealed)?;

        if le.auth.is_some() {
            return token_store.revoke_tree(&le.auth.as_ref().unwrap().client_token);
        }

        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            secret = Some(le.secret.as_ref().unwrap().clone());
        }

        let mut data: Option<Map<String, Value>> = None;
        if !le.data.is_empty() {
            data = Some(le.data.clone());
        }

        let mut req = Request::new_revoke_request(&le.path, secret, data);
        let ret = self.router.handle_request(&mut req);
        if ret.is_err() {
            log::error!("failed to revoke entry: {:?}, err: {}", le, ret.unwrap_err());
        }

        Ok(())
    }

    /// Renews a secret lease entry with a specified increment duration.
    fn renew_secret_lease_entry(&self, le: &LeaseEntry, increment: Duration) -> Result<Option<Response>, RvError> {
        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            let mut s = le.secret.as_ref().unwrap().clone();
            s.lease_id = "".to_string();
            s.increment = increment;
            s.issue_time = Some(le.issue_time);
            secret = Some(s);
        }

        let mut data: Option<Map<String, Value>> = None;
        if !le.data.is_empty() {
            data = Some(le.data.clone());
        }

        let mut req = Request::new_renew_request(&le.path, secret, data);
        let ret = self.router.handle_request(&mut req);
        if ret.is_err() {
            log::error!("failed to renew entry: {}", ret.as_ref().unwrap_err());
        }

        ret
    }

    /// Renews an authentication lease entry with a specified increment duration.
    fn renew_auth_lease_entry(&self, le: &LeaseEntry, increment: Duration) -> Result<Option<Response>, RvError> {
        let mut auth: Option<Auth> = None;
        if le.auth.is_some() {
            let mut au = le.auth.as_ref().unwrap().clone();
            au.client_token = "".to_string();
            au.increment = increment;
            au.issue_time = Some(le.issue_time);
            auth = Some(au);
        }

        let mut req = Request::new_renew_auth_request(&le.path, auth, None);
        let ret = self.router.handle_request(&mut req);
        if ret.is_err() {
            log::error!("failed to renew_auth entry: {}", ret.as_ref().unwrap_err());
        }

        return ret;
    }
}

#[cfg(test)]
mod mode_expiration_tests {
    use std::{sync::Mutex, thread::sleep};

    use serde_json::json;

    use super::*;
    use crate::{
        context::Context,
        logical::{Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Secret},
        mount::{MountEntry, MOUNT_TABLE_TYPE},
        new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
        new_path_internal, new_secret, new_secret_internal,
        test_utils::test_rusty_vault_init,
    };

    macro_rules! new_expiration_manager {
        () => {{
            let name = format!("{}_{}", file!(), line!()).replace("/", "_").replace("\\", "_").replace(".", "_");
            println!("test_rusty_vault_init, name: {}", name);
            let (_, core) = test_rusty_vault_init(&name);
            let core_cloned = core.clone();
            let core_locked = core_cloned.read().unwrap();

            let expiration = ExpirationManager::new(&core_locked).unwrap().wrap();
            let token_store = TokenStore::new(&core_locked, expiration.clone()).unwrap().wrap();

            expiration.set_token_store(&token_store).unwrap();
            expiration.restore().unwrap();
            expiration.start_check_expired_lease_entries();
            (core, expiration, token_store)
        }};
    }

    pub fn renew_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn revoke_noop_handler(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    #[test]
    fn test_secret_expiration() {
        let (core, expiration, _token_store) = new_expiration_manager!();
        let core = core.read().unwrap();
        let new_now: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let new_now_cloned = new_now.clone();
        let renew_flag = Arc::new(Mutex::new(false));
        let renew_flag_cloned = renew_flag.clone();

        let secret = Arc::new(Secret {
            secret_type: "test".into(),
            default_duration: Duration::from_secs(5),
            renew_handler: Some(Arc::new(
                move |_backend: &dyn Backend, req: &mut Request| -> Result<Option<Response>, RvError> {
                    //let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                    let mut renew_flag_cloned_locked = renew_flag_cloned.lock().unwrap();
                    *renew_flag_cloned_locked = true;

                    let mut resp = Response::default();
                    resp.data = req.data.clone();
                    resp.secret = req.secret.clone();
                    Ok(Some(resp))
                },
            )),
            revoke_handler: Some(Arc::new(
                move |_backend: &dyn Backend, _req: &mut Request| -> Result<Option<Response>, RvError> {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
                    let mut new_now_cloned_locked = new_now_cloned.lock().unwrap();
                    *new_now_cloned_locked = now;
                    Ok(None)
                },
            )),
        });
        let secret_cloned = secret.clone();

        let new_backend_fn = move || -> LogicalBackend {
            let mut mock_logical_backend = new_logical_backend!({
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
                    }
                ],
                secrets: [{
                    secret_type: "kv",
                    default_duration: 60,
                    renew_handler: renew_noop_handler,
                    revoke_handler: revoke_noop_handler,
                }],
                unauth_paths: ["/login"],
                root_paths: ["/"],
                help: "help content",
            });

            mock_logical_backend.secrets.push(secret.clone());

            mock_logical_backend
        };

        core.add_logical_backend(
            "test",
            Arc::new(move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
                let mut test_backend = new_backend_fn();
                test_backend.init()?;
                Ok(Arc::new(test_backend))
            }),
        )
        .unwrap();

        let me = MountEntry::new(&MOUNT_TABLE_TYPE, "mytest/", "test", "test description");
        core.mount(&me).unwrap();

        let mut request = Request::new("mytest/tt");
        request.client_token = "mytest".into();

        let mut response = secret_cloned.response(Some(json!({"key": "test"}).as_object().unwrap().clone()), None);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);

        // register secret
        let result = expiration.register_secret(&mut request, &mut response);
        assert!(result.is_ok());

        println!("sleep 10s");
        sleep(Duration::from_secs(10));

        {
            // Check if the `revoke_handler` callback is called when `secret` expires. In `revoke_handler`,
            // we set external variable `new_now` to the current time. `new_now` minus the current time gives the `secret`'s TTL.
            let new_now_locked = new_now.lock().unwrap();
            assert_ne!(*new_now_locked, 0);
            assert!(*new_now_locked - now >= 5);
            assert!(*new_now_locked - now <= 6);
        }

        // register secret again
        //let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|t| t.as_secs()).unwrap_or(0);
        let result = expiration.register_secret(&mut request, &mut response);
        assert!(result.is_ok());

        // test renew
        let lease_id = response.secret.as_ref().unwrap().lease_id.clone();
        let result = expiration.renew(&lease_id, Duration::from_secs(3));
        assert!(result.is_ok());
        let renew_flag_locked = renew_flag.lock().unwrap();
        assert_eq!(*renew_flag_locked, true);

        println!("sleep 10s");
        sleep(Duration::from_secs(10));
        {
            // TODO: The secret's initial TTL is 5s. After a 3s increase during renewal, the TTL should be 8s.
            let new_now_locked = new_now.lock().unwrap();
            assert_ne!(*new_now_locked, 0);
        }
    }

    #[test]
    fn test_auth_expiration() {
        // TODO
        println!("TODO");
    }
}
