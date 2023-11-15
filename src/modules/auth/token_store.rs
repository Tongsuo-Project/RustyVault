use std::{
    sync::Arc,
    ops::Deref,
    time::Duration,
    collections::HashMap,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use humantime::parse_duration;
use crate::{
    util,
    new_path, new_path_internal,
    new_logical_backend, new_logical_backend_internal,
    logical::{
        Auth, Lease,
        Backend, LogicalBackend, Request, Response,
        Operation, Path, PathOperation, Field, FieldType,
    },
    storage::{Storage, StorageEntry},
    core::Core,
    router::Router,
    handler::Handler,
    errors::RvError,
};
use super::{
    AUTH_ROUTER_PREFIX,
    expiration::{ExpirationManager, MAX_LEASE_DURATION_SECS, DEFAULT_LEASE_DURATION_SECS},
};

const TOKEN_LOOKUP_PREFIX: &str = "id/";
const TOKEN_PARENT_PREFIX: &str = "parent/";
const TOKEN_SALT_LOCATION: &str = "salt";
const TOKEN_SUB_PATH: &str = "token/";

static AUTH_TOKEN_HELP: &str = r#"
TODO
"#;

lazy_static! {
    static ref DISPLAY_NAME_SANITIZE: Regex = Regex::new(r"[^a-zA-Z0-9-]").unwrap();
}

#[derive(Serialize, Deserialize)]
struct TokenReqData {
    id: String,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    meta: HashMap<String, String>,
    no_parent: bool,
    #[serde(default)]
    lease: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    num_uses: u32,
    #[serde(default)]
    renewable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub id: String,
    pub parent: String,
    pub policies: Vec<String>,
    pub path: String,
    pub meta: HashMap<String, String>,
    pub display_name: String,
    pub num_uses: u32,
    pub ttl: u64,
}

pub struct TokenStoreInner {
    pub router: Arc<Router>,
    pub view: Option<Arc<dyn Storage + Send + Sync>>,
    pub salt: String,
    pub expiration: Arc<ExpirationManager>,
}

pub struct TokenStore {
    pub inner: Arc<TokenStoreInner>
}

impl Deref for TokenStore {
    type Target = TokenStoreInner;

    fn deref(&self) -> &TokenStoreInner {
        &self.inner
    }
}

impl Default for TokenEntry {
    fn default() -> Self {
        Self {
            id: String::new(),
            parent: String::new(),
            policies: Vec::new(),
            path: String::new(),
            meta: HashMap::new(),
            display_name: String::new(),
            num_uses: 0,
            ttl: 0,
        }
    }
}

impl Default for TokenStoreInner {
    fn default() -> Self {
        Self {
            router: Arc::new(Router::new()),
            view: None,
            salt: String::new(),
            expiration: Arc::new(ExpirationManager::default()),
        }
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        let inner = TokenStoreInner {
            ..TokenStoreInner::default()
        };

        Self {
            inner: Arc::new(inner),
        }
    }
}

impl TokenStore {
    pub fn new(core: &Core, expiration: Arc<ExpirationManager>) -> Result<TokenStore, RvError> {
        if core.system_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut inner = TokenStoreInner::default();

        let view = core.system_view.as_ref().unwrap().new_sub_view(TOKEN_SUB_PATH);
        let salt = view.as_storage().get(TOKEN_SALT_LOCATION)?;

        if salt.is_some() {
            inner.salt = String::from_utf8_lossy(&salt.unwrap().value).to_string();
        }

        if inner.salt.as_str() == "" {
            inner.salt = util::generate_uuid();
            let raw = StorageEntry {
                key: TOKEN_SALT_LOCATION.to_string(),
                value: inner.salt.as_bytes().to_vec(),
            };
            view.as_storage().put(&raw)?;
        }

        inner.router = Arc::clone(&core.router);
        inner.view = Some(Arc::new(view));
        inner.expiration = expiration;

        let token_store = TokenStore {
            inner: Arc::new(inner),
        };

        Ok(token_store)
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let ts_inner_arc1 = Arc::clone(&self.inner);
        let ts_inner_arc2 = Arc::clone(&self.inner);
        let ts_inner_arc3 = Arc::clone(&self.inner);
        let ts_inner_arc4 = Arc::clone(&self.inner);
        let ts_inner_arc5 = Arc::clone(&self.inner);
        let ts_inner_arc6 = Arc::clone(&self.inner);

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "create*",
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc1.handle_create}
                    ],
                    help: "The token create path is used to create new tokens."
                },
                {
                    pattern: "lookup/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to lookup"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: ts_inner_arc2.handle_lookup}
                    ],
                    help: "This endpoint will lookup a token and its properties."
                },
                {
                    pattern: "lookup-self$",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to lookup"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: ts_inner_arc3.handle_lookup}
                    ],
                    help: "This endpoint will lookup a token and its properties."
                },
                {
                    pattern: "revoke/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to revoke"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc4.handle_revoke_tree}
                    ],
                    help: "This endpoint will delete the token and all of its child tokens."
                },
                {
                    pattern: "revoke-orphan/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to revoke (request body)"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc5.handle_revoke_orphan}
                    ],
                    help: "This endpoint will delete the token and orphan its child tokens."
                },
                {
                    pattern: "renew/(?P<token>.+)",
                    fields: {
                        "token": {
                            field_type: FieldType::Str,
                            description: "Token to renew (request body)"
                        },
                        "increment": {
                            field_type: FieldType::Int,
                            description: "The desired increment in seconds to the token expiration"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: ts_inner_arc6.handle_renew}
                    ],
                    help: "This endpoint will renew the token and prevent expiration."
                }
            ],
            root_paths: ["revoke-orphan/*"],
            help: AUTH_TOKEN_HELP
        });

        backend
    }
}

impl TokenStoreInner {
    pub fn salt_id(&self, id: &str) -> String {
        let salted_id = format!("{}{}", self.salt, id);
        util::sha1(salted_id.as_bytes())
    }

    pub fn root_token(&self) -> Result<TokenEntry, RvError> {
        let mut te = TokenEntry {
            policies: vec!["root".to_string()],
            path: "auth/token/root".to_string(),
            display_name: "root".to_string(),
            ..TokenEntry::default()
        };

        self.create(&mut te)?;

        Ok(te)
    }

    pub fn create(&self, entry: &mut TokenEntry) -> Result<(), RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        if entry.id.as_str() == "" {
            entry.id = util::generate_uuid();
        }

        let salted_id = self.salt_id(&entry.id);

        let value = serde_json::to_string(&entry)?;

        if entry.parent.as_str() != "" {
            let parent = self.lookup(&entry.parent)?;
            if parent.is_none() {
                return Err(RvError::ErrAuthTokenNotFound);
            }

            let path = format!("{}{}/{}", TOKEN_PARENT_PREFIX,
                               self.salt_id(&entry.parent), salted_id);
            let entry = StorageEntry {
                key: path,
                ..StorageEntry::default()
            };

            view.put(&entry)?;
        }

        let path = format!("{}{}", TOKEN_LOOKUP_PREFIX, salted_id);
        let entry = StorageEntry {
            key: path,
            value: value.as_bytes().to_vec(),
        };

        view.put(&entry)
    }

    pub fn use_token(&self, entry: &mut TokenEntry) -> Result<(), RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        if entry.num_uses == 0{
            return Ok(());
        }

        entry.num_uses -= 1;

        if entry.num_uses == 0{
            return self.revoke(&entry.id);
        }

        let salted_id = self.salt_id(&entry.id);
        let value = serde_json::to_string(&entry)?;

        let path = format!("{}{}", TOKEN_LOOKUP_PREFIX, salted_id);
        let entry = StorageEntry {
            key: path,
            value: value.as_bytes().to_vec(),
        };

        view.put(&entry)
    }

    pub fn check_token(&self, _path: &str, token: &str) -> Result<Option<Auth>, RvError> {
        if token == "" {
            return Err(RvError::ErrRequestClientTokenMissing);
        }

        log::debug!("check token: {}", token);
        let te = self.lookup(token)?;
        if te.is_none() {
            return Err(RvError::ErrPermissionDenied);
        }

        let mut entry = te.unwrap();

        self.use_token(&mut entry)?;

        let auth = Auth {
            client_token: token.to_string(),
            display_name: entry.display_name,
            policies: entry.policies.clone(),
            metadata: entry.meta,
            ..Auth::default()
        };

        Ok(Some(auth))
    }

    pub fn lookup(&self, id: &str) -> Result<Option<TokenEntry>, RvError> {
        if id == "" {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.lookup_salted(self.salt_id(id).as_str())
    }

    pub fn lookup_salted(&self, salted_id: &str) -> Result<Option<TokenEntry>, RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        let path = format!("{}{}", TOKEN_LOOKUP_PREFIX, salted_id);
        let raw = view.get(&path)?;
        if raw.is_none() {
            return Ok(None);
        }

        let entry: TokenEntry = serde_json::from_slice(raw.unwrap().value.as_slice())?;

        Ok(Some(entry))
    }

    pub fn revoke(&self, id: &str) -> Result<(), RvError> {
        if id == "" {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.revoke_salted(self.salt_id(id).as_str())
    }

    pub fn revoke_salted(&self, salted_id: &str) -> Result<(), RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        let entry = self.lookup_salted(salted_id)?;

        let path = format!("{}{}", TOKEN_LOOKUP_PREFIX, salted_id);

        view.delete(&path)?;

        if entry.is_some() {
            let entry = entry.unwrap();
            if entry.parent.as_str() != "" {
                let path = format!("{}{}/{}", TOKEN_PARENT_PREFIX,
                                   self.salt_id(&entry.parent), salted_id);
                view.delete(&path)?;
            }
            //Revoke all secrets under this token
            self.expiration.revoke_by_token(&entry.id)?;
        }

        Ok(())
    }

    pub fn revoke_tree(&self, id: &str) -> Result<(), RvError> {
        if id == "" {
            return Err(RvError::ErrAuthTokenIdInvalid);
        }

        self.revoke_tree_salted(self.salt_id(id).as_str())
    }

    pub fn revoke_tree_salted(&self, salted_id: &str) -> Result<(), RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        let path = format!("{}{}/", TOKEN_PARENT_PREFIX, salted_id);

        let children = view.list(&path)?;
        for child in children.iter() {
            self.revoke_tree_salted(&child)?;
        }

        self.revoke_salted(salted_id)
    }

    pub fn handle_create(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let parent = self.lookup(&req.client_token)?;
        if parent.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let parent = parent.unwrap();
        if parent.num_uses > 0 {
            return Err(RvError::ErrRequestInvalid);
        }

        let is_root = parent.policies.iter().any(|s| s.as_str() == "root");

        let mut data: TokenReqData = serde_json::from_value(Value::Object(req.body.as_ref().unwrap().clone()))?;

        let mut te = TokenEntry {
            parent: req.client_token.clone(),
            path: "auth/token/create".to_string(),
            meta: data.meta.clone(),
            display_name: "token".to_string(),
            num_uses: data.num_uses,
            ..TokenEntry::default()
        };

        let renewable = data.renewable;

        if data.display_name.as_str() != "" {
            let mut full = format!("token-{}", data.display_name);
            full = DISPLAY_NAME_SANITIZE.replace_all(&full, "-").to_string();
            full = full.trim_end_matches('-').to_string();
            te.display_name = full;
        }

        if data.id.as_str() != "" {
            if !is_root {
                return Err(RvError::ErrRequestInvalid);
            }
            te.id = data.id.clone();
        }

        if data.policies.len() == 0 {
            data.policies = parent.policies.clone();
        }

        if !is_root && !util::is_str_subset(&data.policies, &parent.policies) {
            return Err(RvError::ErrRequestInvalid);
        }

        te.policies = data.policies.clone();

        if data.no_parent {
            if !is_root {
                return Err(RvError::ErrRequestInvalid);
            }
            te.parent = "".to_string();
        }

        if data.ttl.as_str() != "" {
            let dur = parse_duration(&data.ttl)?;
            te.ttl = dur.as_secs();
        } else if data.lease.as_str() != "" {
            let dur = parse_duration(&data.lease)?;
            te.ttl = dur.as_secs();
        }

        self.create(&mut te)?;

        let auth = Auth {
            lease: Lease {
                ttl: Duration::from_secs(te.ttl),
                renewable: renewable,
                ..Lease::default()
            },
            client_token: te.id.clone(),
            display_name: te.display_name.clone(),
            policies: te.policies.clone(),
            metadata: te.meta.clone(),
        };
        let resp = Response {
            auth: Some(auth),
            ..Response::default()
        };

        Ok(Some(resp))
    }

    pub fn handle_revoke_tree(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = req.get_data("token")?;
        let id = id.as_str().unwrap();
        if id == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        self.revoke_tree(id)?;

        Ok(None)
    }

    pub fn handle_revoke_orphan(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = req.get_data("token")?;
        let id = id.as_str().unwrap();
        if id == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        self.revoke(id)?;

        Ok(None)
    }

    pub fn handle_lookup(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = req.get_data("token")?;
        let mut id = id.as_str().unwrap();
        if id == "" {
            id = &req.client_token;
        }

        if id == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        let te = self.lookup(id)?;
        if te.is_none() {
            return Ok(None);
        }

        let te = te.unwrap();

        let meta = serde_json::to_value(&te.meta)?;

        let data = serde_json::json!({
            "id": te.id.clone(),
            "policies": te.policies.clone(),
            "path": te.path.clone(),
            "meta": meta,
            "display_name": te.display_name.clone(),
            "num_uses": te.num_uses,
            "ttl": te.ttl,
        }).as_object().unwrap().clone();

        Ok(Some(Response::data_response(Some(data))))
    }

    pub fn handle_renew(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let id = req.get_data("token")?;
        let id = id.as_str().unwrap();
        if id == "" {
            return Err(RvError::ErrRequestInvalid);
        }

        let te = self.lookup(&id)?;
        if te.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }
        let te = te.unwrap();

        let increment_raw: i32 = serde_json::from_value(req.get_data("increment")?)?;
        let increment = Duration::from_secs(increment_raw as u64);

        let auth = self.expiration.renew_token(&te.path, &te.id, increment)?;

        let resp = Response {
            auth: auth,
            ..Response::default()
        };

        Ok(Some(resp))
    }
}

impl Handler for TokenStore {
    fn name(&self) -> String {
        "auth_token".to_string()
    }

    fn pre_route(&self, req: &mut Request) -> Result<Option<Response>, RvError> {
        let is_unauth_path = self.router.is_unauth_path(&req.path)?;
        if is_unauth_path {
            return Ok(None);
        }

        let auth = self.check_token(&req.path, &req.client_token)?;
        if auth.is_none() {
            return Err(RvError::ErrPermissionDenied);
        }

        req.name = auth.as_ref().unwrap().display_name.clone();

        Ok(None)
    }

    fn post_route(&self, req: &mut Request, resp: &mut Option<Response>) -> Result<(), RvError> {
        if resp.is_none() {
            return Ok(());
        }

        let is_unauth_path = self.router.is_unauth_path(&req.path)?;

        let resp = resp.as_mut().unwrap();

        if !is_unauth_path && resp.secret.is_some() {
            self.expiration.register_secret(req, resp)?;
        }

        if let Some(auth) = resp.auth.as_mut() {
            if is_unauth_path {
                let source = self.router.matching_mount(&req.path)?;
                let source = source.as_str().trim_start_matches(AUTH_ROUTER_PREFIX).replace("/", "-");
                auth.display_name = (source + &auth.display_name).trim_end_matches("-").to_string();
                req.name = auth.display_name.clone();
            } else {
                if !req.path.starts_with("auth/token/") {
                    return Err(RvError::ErrPermissionDenied);
                }
            }

            if auth.ttl.as_secs() == 0 {
                auth.ttl = DEFAULT_LEASE_DURATION_SECS;
            }

            if auth.ttl > MAX_LEASE_DURATION_SECS {
                auth.ttl = MAX_LEASE_DURATION_SECS;
            }

            self.expiration.register_auth(&req.path, auth)?;
        }

        Ok(())
    }
}
