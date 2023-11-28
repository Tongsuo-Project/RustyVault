use std::{
    collections::HashMap,
    ops::Deref,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use delay_timer::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::TokenStore;
use crate::{
    core::Core,
    errors::RvError,
    logical::{Auth, Request, Response, SecretData},
    router::Router,
    storage::{barrier_view::BarrierView, StorageEntry},
    utils::{deserialize_system_time, generate_uuid, serialize_system_time},
};

pub const EXPIRATION_SUB_PATH: &str = "expire/";
pub const LEASE_VIEW_PREFIX: &str = "id/";
pub const TOKEN_VIEW_PREFIX: &str = "token/";
pub const MAX_REVOKE_ATTEMPTS: u32 = 6;
pub const REVOKE_RETRY_SECS: Duration = Duration::from_secs(10);
pub const MIN_REVOKE_DELAY_SECS: Duration = Duration::from_secs(5);
pub const MAX_LEASE_DURATION_SECS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_LEASE_DURATION_SECS: Duration = MAX_LEASE_DURATION_SECS;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseEntry {
    #[serde(default)]
    pub lease_id: String,
    pub client_token: String,
    pub path: String,
    pub data: Option<HashMap<String, Value>>,
    pub secret: Option<SecretData>,
    pub auth: Option<Auth>,
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub issue_time: SystemTime,
    #[serde(serialize_with = "serialize_system_time", deserialize_with = "deserialize_system_time")]
    pub expire_time: SystemTime,
}

pub struct ExpirationTask {
    pub last_task_id: u64,
    pub task_id_map: HashMap<String, u64>,
    pub task_id_remove_pending: Vec<u64>,
    pub task_timer: DelayTimer,
}

pub struct ExpirationManagerInner {
    pub router: Option<Arc<Router>>,
    pub id_view: Option<Arc<BarrierView>>,
    pub token_view: Option<Arc<BarrierView>>,
    pub token_store: Arc<RwLock<Option<Arc<TokenStore>>>>,
    pub task: RwLock<ExpirationTask>,
}

pub struct ExpirationManager {
    pub inner: Arc<ExpirationManagerInner>,
}

impl Default for ExpirationTask {
    fn default() -> Self {
        Self {
            last_task_id: 0,
            task_id_map: HashMap::new(),
            task_id_remove_pending: Vec::new(),
            task_timer: DelayTimerBuilder::default().build(),
        }
    }
}

impl Default for ExpirationManagerInner {
    fn default() -> Self {
        Self {
            router: None,
            id_view: None,
            token_view: None,
            token_store: Arc::new(RwLock::new(None)),
            task: RwLock::new(ExpirationTask::default()),
        }
    }
}

impl Default for ExpirationManager {
    fn default() -> Self {
        Self { inner: Arc::new(ExpirationManagerInner::default()) }
    }
}

impl Deref for ExpirationManager {
    type Target = ExpirationManagerInner;

    fn deref(&self) -> &ExpirationManagerInner {
        &self.inner
    }
}

impl LeaseEntry {
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

impl ExpirationTask {
    fn add_task<F: Fn() -> U + 'static + Send, U: std::future::Future + 'static + Send>(
        &mut self,
        lease_id: &str,
        ttl: u64,
        routine: F,
    ) -> Result<(), RvError> {
        self.clean_finish_task()?;

        self.last_task_id += 1;
        let mut task_builder = TaskBuilder::default();

        let task = task_builder
            .set_task_id(self.last_task_id)
            .set_frequency_once_by_seconds(ttl)
            .spawn_async_routine(routine)?;

        self.task_timer.add_task(task)?;
        self.task_id_map.insert(lease_id.to_string(), self.last_task_id);

        log::debug!("add task, lease_id: {}, task_id: {}, ttl: {}", lease_id, self.last_task_id, ttl);

        Ok(())
    }

    fn update_task<F: Fn() -> U + 'static + Send, U: std::future::Future + 'static + Send>(
        &mut self,
        lease_id: &str,
        ttl: u64,
        routine: F,
    ) -> Result<(), RvError> {
        let task_id = self.task_id_map.get(lease_id);
        log::debug!("update task, lease_id: {}, ttl: {}", lease_id, ttl);
        if task_id.is_none() && ttl > 0 {
            return self.add_task(lease_id, ttl, routine);
        }

        if task_id.is_some() {
            self.remove_task(lease_id)?;
            if ttl > 0 {
                return self.add_task(lease_id, ttl, routine);
            }
        }

        Ok(())
    }

    fn remove_task(&mut self, lease_id: &str) -> Result<(), RvError> {
        log::debug!("remove task, lease_id: {}", lease_id);
        if let Some(task_id) = self.task_id_map.remove(lease_id) {
            self.task_id_remove_pending.push(task_id);
        }
        Ok(())
    }

    fn clean_finish_task(&mut self) -> Result<(), RvError> {
        for task_id in self.task_id_remove_pending.iter() {
            log::debug!("clean finish task, task_id: {}", *task_id);
            self.task_timer.remove_task(*task_id)?;
        }
        self.task_id_remove_pending.clear();
        Ok(())
    }
}

impl Drop for ExpirationTask {
    fn drop(&mut self) {
        log::debug!("expiration task timer stopping!");
        let _ = self.task_timer.stop_delay_timer();
    }
}

impl ExpirationManager {
    pub fn new(core: &Core) -> Result<ExpirationManager, RvError> {
        if core.system_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = core.system_view.as_ref().unwrap().new_sub_view(LEASE_VIEW_PREFIX);
        let token_view = core.system_view.as_ref().unwrap().new_sub_view(TOKEN_VIEW_PREFIX);

        let mut inner = ExpirationManagerInner::default();
        inner.router = Some(Arc::clone(&core.router));
        inner.id_view = Some(Arc::new(id_view));
        inner.token_view = Some(Arc::new(token_view));

        let expiration = ExpirationManager { inner: Arc::new(inner) };

        Ok(expiration)
    }

    pub fn cleanup(&self) -> Result<(), RvError> {
        Ok(())
    }

    pub fn set_token_store(&self, ts: Arc<TokenStore>) -> Result<(), RvError> {
        let mut token_store = self.token_store.write()?;
        *token_store = Some(ts);
        Ok(())
    }

    pub fn restore(&self) -> Result<(), RvError> {
        if self.id_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = self.id_view.as_ref().unwrap();
        let existing = id_view.get_keys()?;

        for lease_id in existing {
            let le = self.load_entry(&lease_id)?;
            if le.is_none() {
                continue;
            }
            let le = le.unwrap();

            self.add_task(&le)?
        }

        Ok(())
    }

    pub fn renew(&self, lease_id: &str, increment: Duration) -> Result<Option<Response>, RvError> {
        let le = self.load_entry(&lease_id)?;
        if le.is_none() {
            return Err(RvError::ErrLeaseNotFound);
        }

        let mut le = le.unwrap();

        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }

        let resp = self.renew_entry(&le, increment)?;
        if resp.is_none() {
            return Ok(None);
        }

        let mut resp = resp.unwrap();
        if resp.secret.is_none() || !resp.secret.as_ref().unwrap().enabled() {
            return Ok(Some(resp));
        }

        let ttl = resp.secret.as_ref().unwrap().ttl().as_secs();
        resp.secret.as_mut().unwrap().lease_id = lease_id.to_string();

        le.data = resp.data.clone().map(|serde_map| serde_map.into_iter().collect());
        le.expire_time = resp.secret.as_ref().unwrap().expiration_time();
        le.secret = resp.secret.clone();

        self.persist_entry(&le)?;

        self.update_task(&le, ttl)?;

        Ok(Some(resp))
    }

    pub fn renew_token(&self, source: &str, token: &str, increment: Duration) -> Result<Option<Auth>, RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        let src = PathBuf::from(source);
        let lease_id = src.join(token_store.salt_id(token)).to_string_lossy().to_string();

        let le = self.load_entry(&lease_id)?;
        if le.is_none() {
            return Err(RvError::ErrLeaseNotFound);
        }

        let mut le = le.unwrap();

        if !le.renewable() {
            return Err(RvError::ErrLeaseNotRenewable);
        }

        let resp = self.renew_auth_entry(&le, increment)?;
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

        let ttl = auth.ttl().as_secs();

        auth.client_token = token.to_string();
        auth.increment = Duration::from_secs(0);
        auth.issue_time = Some(SystemTime::now());

        le.expire_time = auth.expiration_time();
        le.auth = Some(auth.clone());

        self.persist_entry(&le)?;

        self.update_task(&le, ttl)?;

        Ok(Some(auth))
    }

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

            let le = LeaseEntry {
                lease_id,
                client_token: req.client_token.clone(),
                path: req.path.clone(),
                data: resp.data.clone().map(|serde_map| serde_map.into_iter().collect()),
                secret: Some(secret.clone()),
                auth: None,
                issue_time: now,
                expire_time: secret.expiration_time(),
            };

            self.persist_entry(&le)?;
            self.index_by_token(&le.client_token, &le.lease_id)?;
            self.update_task(&le, secret.ttl().as_secs())?;

            secret.lease_id = le.lease_id;
        }

        Ok(())
    }

    pub fn register_auth(&self, source: &str, auth: &mut Auth) -> Result<(), RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        let src = PathBuf::from(source);
        let lease_id = src.join(token_store.salt_id(&auth.client_token)).to_string_lossy().to_string();

        let now = SystemTime::now();
        auth.issue_time = Some(now);

        let le = LeaseEntry {
            lease_id,
            client_token: auth.client_token.clone(),
            path: source.to_string(),
            data: None,
            secret: None,
            auth: Some(auth.clone()),
            issue_time: now,
            expire_time: auth.expiration_time(),
        };

        self.persist_entry(&le)?;
        self.update_task(&le, auth.ttl().as_secs())?;

        Ok(())
    }

    fn add_task(&self, entry: &LeaseEntry) -> Result<(), RvError> {
        let lease_id = entry.lease_id.clone();
        let now = SystemTime::now();
        let mut expire_time = MIN_REVOKE_DELAY_SECS;
        if entry.expire_time > now {
            expire_time = entry.expire_time.duration_since(now)?;
        }

        let expiration = Arc::clone(&self.inner);

        let mut task = self.task.write()?;

        let rt = move || {
            let expiration_ref = Arc::clone(&expiration);
            let id = lease_id.clone();
            async move {
                expiration_ref.expire_id(&id);
            }
        };

        task.add_task(&entry.lease_id, expire_time.as_secs(), rt)
    }

    fn update_task(&self, entry: &LeaseEntry, expire_secs: u64) -> Result<(), RvError> {
        let lease_id = entry.lease_id.clone();

        let expiration = Arc::clone(&self.inner);

        let mut task = self.task.write()?;

        let rt = move || {
            let expiration_ref = Arc::clone(&expiration);
            let id = lease_id.clone();
            async move {
                expiration_ref.expire_id(&id);
            }
        };

        task.update_task(&entry.lease_id, expire_secs, rt)
    }
}

impl ExpirationManagerInner {
    fn expire_id(&self, lease_id: &str) {
        for i in 0..MAX_REVOKE_ATTEMPTS {
            let ret = self.revoke(lease_id);
            if ret.is_ok() {
                return;
            }

            log::error!("expire: failed to revoke {}, err: {}", lease_id, ret.unwrap_err());
            std::thread::sleep(Duration::from_secs((1 << i) * REVOKE_RETRY_SECS.as_secs()));
        }

        log::error!("expire: maximum revoke attempts for '{}' reached", lease_id);
    }

    fn load_entry(&self, lease_id: &str) -> Result<Option<LeaseEntry>, RvError> {
        if self.id_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = self.id_view.as_ref().unwrap().as_storage();

        let raw = id_view.get(lease_id)?;
        if raw.is_none() {
            return Ok(None);
        }

        let le: LeaseEntry = serde_json::from_slice(raw.unwrap().value.as_slice())?;

        Ok(Some(le))
    }

    fn persist_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        if self.id_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = self.id_view.as_ref().unwrap().as_storage();

        let value = serde_json::to_string(&le)?;

        let entry = StorageEntry { key: le.lease_id.clone(), value: value.as_bytes().to_vec() };

        id_view.put(&entry)
    }

    fn delete_entry(&self, lease_id: &str) -> Result<(), RvError> {
        if self.id_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let id_view = self.id_view.as_ref().unwrap().as_storage();

        id_view.delete(lease_id)
    }

    fn index_by_token(&self, token: &str, lease_id: &str) -> Result<(), RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() || self.token_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        let token_view = self.token_view.as_ref().unwrap().as_storage();

        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));

        let entry = StorageEntry { key, value: lease_id.as_bytes().to_owned() };

        token_view.put(&entry)
    }

    /*
    fn remove_index_by_token(&self, token: &str, lease_id: &str) -> Result<(), RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() || self.token_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        let token_view = self.token_view.as_ref().unwrap().as_storage();

        let key = format!("{}/{}", token_store.salt_id(token), token_store.salt_id(lease_id));

        token_view.delete(&key)
    }
    */

    fn lookup_by_token(&self, token: &str) -> Result<Vec<String>, RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() || self.token_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        let token_view = self.token_view.as_ref().unwrap().as_storage();
        let prefix = format!("{}/", token_store.salt_id(token));
        let sub_keys = token_view.list(&prefix)?;

        let mut ret: Vec<String> = Vec::new();

        for sub in sub_keys.iter() {
            let key = format!("{}{}", prefix, sub);
            let raw = token_view.get(&key)?;
            if raw.is_none() {
                continue;
            }

            let lease_id = String::from_utf8_lossy(&raw.unwrap().value).to_string();
            ret.push(lease_id);
        }

        Ok(ret)
    }

    fn revoke_entry(&self, le: &LeaseEntry) -> Result<(), RvError> {
        let token_store = self.token_store.read()?;
        if token_store.is_none() || self.router.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let token_store = token_store.as_ref().unwrap();

        if le.auth.is_some() {
            return token_store.revoke_tree(&le.auth.as_ref().unwrap().client_token);
        }

        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            secret = Some(le.secret.as_ref().unwrap().clone());
        }

        let mut data: Option<Map<String, Value>> = None;
        if le.data.is_some() {
            data = Some(Map::from_iter(le.data.as_ref().unwrap().iter().map(|(k, v)| (k.clone(), v.clone()))));
        }

        let mut req = Request::new_revoke_request(&le.path, secret, data);
        let ret = self.router.as_ref().unwrap().as_handler().route(&mut req);
        if ret.is_err() {
            log::error!("failed to revoke entry: {:?}, err: {}", le, ret.unwrap_err());
        }

        Ok(())
    }

    fn renew_entry(&self, le: &LeaseEntry, increment: Duration) -> Result<Option<Response>, RvError> {
        if self.router.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut secret: Option<SecretData> = None;
        if le.secret.is_some() {
            let mut s = le.secret.as_ref().unwrap().clone();
            s.lease_id = "".to_string();
            s.increment = increment;
            s.issue_time = Some(le.issue_time);
            secret = Some(s);
        }

        let mut data: Option<Map<String, Value>> = None;
        if le.data.is_some() {
            data = Some(Map::from_iter(le.data.as_ref().unwrap().iter().map(|(k, v)| (k.clone(), v.clone()))));
        }

        let mut req = Request::new_renew_request(&le.path, secret, data);
        let ret = self.router.as_ref().unwrap().as_handler().route(&mut req);
        if ret.is_err() {
            log::error!("failed to renew entry: {}", ret.as_ref().unwrap_err());
        }

        ret
    }

    fn renew_auth_entry(&self, le: &LeaseEntry, increment: Duration) -> Result<Option<Response>, RvError> {
        if self.router.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut auth: Option<Auth> = None;
        if le.auth.is_some() {
            let mut au = le.auth.as_ref().unwrap().clone();
            au.client_token = "".to_string();
            au.increment = increment;
            au.issue_time = Some(le.issue_time);
            auth = Some(au);
        }

        let mut req = Request::new_renew_auth_request(&le.path, auth, None);
        let ret = self.router.as_ref().unwrap().as_handler().route(&mut req);
        if ret.is_err() {
            log::error!("failed to renew_auth entry: {}", ret.as_ref().unwrap_err());
        }

        return ret;
    }

    fn delete_task(&self, lease_id: &str) -> Result<(), RvError> {
        let mut task = self.task.write()?;
        task.remove_task(lease_id)
    }

    pub fn revoke(&self, lease_id: &str) -> Result<(), RvError> {
        let le = self.load_entry(lease_id)?;
        if le.is_none() {
            return Ok(());
        }

        let le = le.unwrap();

        log::debug!("revoke lease_id: {}", &le.lease_id);

        self.revoke_entry(&le)?;
        self.delete_entry(lease_id)?;
        self.index_by_token(&le.client_token, &le.lease_id)?;
        self.delete_task(&le.lease_id)?;

        Ok(())
    }

    pub fn revoke_prefix(&self, prefix: &str) -> Result<(), RvError> {
        if self.id_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut prefix = prefix.to_string();
        if !prefix.ends_with("!") {
            prefix += "/";
        }

        let id_view = self.id_view.as_ref().unwrap();
        let sub = id_view.new_sub_view(&prefix);
        let existing = sub.get_keys()?;
        for suffix in existing.iter() {
            let lease_id = format!("{}{}", prefix, suffix);
            self.revoke(&lease_id)?;
        }

        Ok(())
    }

    pub fn revoke_by_token(&self, token: &str) -> Result<(), RvError> {
        let existing = self.lookup_by_token(token)?;
        for lease_id in existing.iter() {
            self.revoke(&lease_id)?;
        }

        Ok(())
    }
}
