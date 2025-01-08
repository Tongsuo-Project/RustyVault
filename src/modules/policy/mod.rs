use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use better_default::Default;
use serde_json::{Map, Value};

use super::Module;
use crate::{
    core::Core,
    errors::RvError,
    handler::AuthHandler,
    logical::{Backend, Request, Response},
};

pub mod policy;
pub use policy::{Permissions, Policy, PolicyPathRules, PolicyType};

pub mod policy_store;
pub use policy_store::PolicyStore;

pub mod acl;

#[derive(Default)]
pub struct PolicyModule {
    #[default("policy".into())]
    pub name: String,
    pub core: Arc<RwLock<Core>>,
    pub policy_store: Arc<PolicyStore>,
}

impl PolicyModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "policy".into(),
            core: Arc::clone(core.self_ref.as_ref().unwrap()),
            policy_store: Arc::new(PolicyStore::default()),
        }
    }

    pub fn setup_policy(&mut self) -> Result<(), RvError> {
        self.policy_store.load_default_acl_policy()
    }

    pub fn handle_policy_list(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let policies = self.policy_store.list_policy(PolicyType::Acl)?;
        let mut resp = Response::list_response(&policies);
        if req.path.starts_with("policy") {
            let data = resp.data.as_mut().unwrap();
            data.insert("policies".into(), data["keys"].clone());
        }
        Ok(Some(resp))
    }

    pub fn handle_policy_read(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        if let Some(policy) = self.policy_store.get_policy(&name, PolicyType::Acl)? {
            let mut resp_data = Map::new();
            resp_data.insert("name".into(), Value::String(name));

            // If the request is from sys/policy/ we handle backwards compatibility
            if req.path.starts_with("policy") {
                resp_data.insert("rules".into(), Value::String(policy.raw.clone()));
            } else {
                resp_data.insert("policy".into(), Value::String(policy.raw.clone()));
            }

            let resp = Response::data_response(Some(resp_data));
            if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
                policy.add_sentinel_policy_data(&resp)?;
            }

            return Ok(Some(resp));
        }
        Ok(None)
    }

    pub fn handle_policy_write(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let policy_str = req.get_data_as_str("policy")?;
        let policy_raw = if let Ok(policy_bytes) = STANDARD.decode(&policy_str) {
            String::from_utf8_lossy(&policy_bytes).to_string()
        } else {
            policy_str
        };

        let mut policy = Policy::from_str(&policy_raw)?;
        policy.name = name;

        if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
            policy.input_sentinel_policy_data(req)?;
        }

        self.policy_store.set_policy(policy)?;

        Ok(None)
    }

    pub fn handle_policy_delete(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        self.policy_store.delete_policy(&name, PolicyType::Acl)?;
        Ok(None)
    }
}

impl Module for PolicyModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn init(&mut self, core: &Core) -> Result<(), RvError> {
        self.policy_store = PolicyStore::new(core)?;

        self.setup_policy()?;

        core.add_auth_handler(Arc::clone(&self.policy_store) as Arc<dyn AuthHandler>)?;

        Ok(())
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_auth_handler(Arc::clone(&self.policy_store) as Arc<dyn AuthHandler>)?;
        self.policy_store = Arc::new(PolicyStore::default());
        Ok(())
    }
}
