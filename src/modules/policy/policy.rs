use std::{collections::HashMap, str::FromStr, time::Duration};

use better_default::Default;
use dashmap::DashMap;
use derive_more::Display;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use strum::IntoEnumIterator;
use strum_macros::{Display as StrumDisplay, EnumIter, EnumString};

use super::acl::ACLResults;
use crate::{
    errors::RvError,
    logical::{auth::PolicyInfo, Operation, Request, Response},
    rv_error_string,
    utils::{deserialize_duration, string::ensure_no_leading_slash},
};

#[derive(Display, Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    #[display(fmt = "acl")]
    Acl,
    #[display(fmt = "rgp")]
    Rgp,
    #[display(fmt = "egp")]
    Egp,
    #[display(fmt = "token")]
    Token,
}

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct SentinelPolicy {}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub sentinal_policy: SentinelPolicy,
    pub name: String,
    pub paths: Vec<PolicyPathRules>,
    pub raw: String,
    #[default(PolicyType::Acl)]
    pub policy_type: PolicyType,
    pub templated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyPathRules {
    pub path: String,
    pub permissions: Permissions,
    pub capabilities: Vec<Capability>,
    pub is_prefix: bool,
    pub has_segment_wildcards: bool,
    pub min_wrapping_ttl: Duration,
    pub max_wrapping_ttl: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct Permissions {
    pub capabilities_bitmap: u32,
    pub min_wrapping_ttl: Duration,
    pub max_wrapping_ttl: Duration,
    pub allowed_parameters: Map<String, Value>,
    pub denied_parameters: Map<String, Value>,
    pub required_parameters: Vec<String>,
    pub granting_policies_map: DashMap<u32, Vec<PolicyInfo>>,
}

#[derive(Debug, Deserialize)]
struct PolicyConfig {
    pub path: HashMap<String, PolicyPathConfig>,
}

#[derive(Debug, Deserialize)]
struct PolicyPathConfig {
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default, deserialize_with = "deserialize_duration")]
    pub min_wrapping_ttl: Duration,
    #[serde(default, deserialize_with = "deserialize_duration")]
    pub max_wrapping_ttl: Duration,
    #[serde(default)]
    pub allowed_parameters: Map<String, Value>,
    #[serde(default)]
    pub denied_parameters: Map<String, Value>,
    #[serde(default)]
    pub required_parameters: Vec<String>,
}

#[derive(Debug, StrumDisplay, Copy, Clone, EnumString, EnumIter, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u32)]
pub enum Capability {
    #[strum(to_string = "deny")]
    Deny = 1 << 0,
    #[strum(to_string = "create")]
    Create = 1 << 1,
    #[strum(to_string = "read")]
    Read = 1 << 2,
    #[strum(to_string = "update")]
    Update = 1 << 3,
    #[strum(to_string = "delete")]
    Delete = 1 << 4,
    #[strum(to_string = "list")]
    List = 1 << 5,
    #[strum(to_string = "sudo")]
    Sudo = 1 << 6,
    #[strum(to_string = "patch")]
    Patch = 1 << 7,
}

impl Capability {
    pub fn to_bits(&self) -> u32 {
        *self as u32
    }
}

impl FromStr for Policy {
    type Err = RvError;

    fn from_str(s: &str) -> Result<Self, RvError> {
        //let policy_config: PolicyConfig = hcl::from_str(s)?;
        let policy_config =
            if let Ok(pc) = hcl::from_str::<PolicyConfig>(s) { pc } else { serde_json::from_str::<PolicyConfig>(s)? };

        let mut policy = Policy::default();
        policy.raw = s.to_string();

        for (path, pc) in policy_config.path.iter() {
            if path.contains("+*") {
                return Err(rv_error_string!(&format!("path {}: invalid use of wildcards ('+*' is forbidden)", path)));
            }

            let mut rules = PolicyPathRules::default();
            rules.path = ensure_no_leading_slash(&path);
            rules.capabilities = pc.capabilities.clone();
            rules.min_wrapping_ttl = pc.min_wrapping_ttl;
            rules.max_wrapping_ttl = pc.max_wrapping_ttl;

            if rules.path == "+" || rules.path.contains("/+") || rules.path.starts_with("+/") {
                rules.has_segment_wildcards = true;
            }

            // If there are segment wildcards, don't actually strip the
            // trailing asterisk, but don't want to hit the default case
            if rules.path.ends_with("*") {
                if !rules.has_segment_wildcards {
                    rules.path = rules.path.trim_end_matches("*").to_string();
                    rules.is_prefix = true;
                }
            }

            let permissions = &mut rules.permissions;
            permissions.capabilities_bitmap = rules.capabilities.iter().fold(0u32, |acc, cap| acc | cap.to_bits());
            if permissions.capabilities_bitmap & Capability::Deny.to_bits() != 0 {
                // If it's deny, don't include any other capability
                permissions.capabilities_bitmap = Capability::Deny.to_bits();
                rules.capabilities = vec![Capability::Deny];
            }

            for (param_key, param_value) in pc.allowed_parameters.iter() {
                if !param_value.is_array() {
                    return Err(rv_error_string!(&format!(
                        "path {}: invalid allowed_parameters: {:?} is not an array",
                        path, param_value
                    )));
                }

                permissions.allowed_parameters.insert(param_key.to_lowercase(), param_value.clone());
            }

            for (param_key, param_value) in pc.denied_parameters.iter() {
                if !param_value.is_array() {
                    return Err(rv_error_string!(&format!(
                        "path {}: invalid denied_parameters: {:?} is not an array",
                        path, param_value
                    )));
                }

                permissions.denied_parameters.insert(param_key.to_lowercase(), param_value.clone());
            }

            permissions.min_wrapping_ttl = pc.min_wrapping_ttl;
            permissions.max_wrapping_ttl = pc.max_wrapping_ttl;
            permissions.required_parameters = pc.required_parameters.clone();

            policy.paths.push(rules);
        }

        Ok(policy)
    }
}

impl Policy {
    pub fn input_sentinel_policy_data(&mut self, _req: &Request) -> Result<(), RvError> {
        Ok(())
    }

    pub fn add_sentinel_policy_data(&self, _resp: &Response) -> Result<(), RvError> {
        Ok(())
    }
}

impl Permissions {
    pub fn check(&self, req: &Request, check_only: bool) -> Result<ACLResults, RvError> {
        let mut ret = ACLResults::default();
        let _path = ensure_no_leading_slash(&req.path);

        ret.root_privs = (self.capabilities_bitmap & Capability::Sudo.to_bits()) != 0;

        if check_only {
            ret.capabilities_bitmap = self.capabilities_bitmap;
            return Ok(ret);
        }

        let cap = match req.operation {
            Operation::Read => Capability::Read,
            Operation::List => Capability::List,
            Operation::Write => Capability::Update,
            Operation::Delete => Capability::Delete,
            Operation::Renew | Operation::Revoke | Operation::Rollback => Capability::Update,
            _ => return Ok(ret),
        };

        if self.capabilities_bitmap & cap.to_bits() == 0 {
            if req.operation != Operation::Write || self.capabilities_bitmap & Capability::Create.to_bits() == 0 {
                return Ok(ret);
            }
        }

        if let Some(value) = self.granting_policies_map.get(&cap.to_bits()) {
            ret.granting_policies = value.clone();
        }

        let zero_ttl = Duration::from_secs(0);

        if self.max_wrapping_ttl > zero_ttl {
            // TODO
        }

        if self.min_wrapping_ttl > zero_ttl {
            // TODO
        }

        if self.min_wrapping_ttl != zero_ttl
            && self.max_wrapping_ttl != zero_ttl
            && self.max_wrapping_ttl < self.min_wrapping_ttl
        {
            return Ok(ret);
        }

        match req.operation {
            // Only check parameter permissions for operations that can modify parameters.
            Operation::Read | Operation::Write => {
                for parameter in self.required_parameters.iter() {
                    if !req.get_data(parameter.to_lowercase().as_str()).is_ok() {
                        return Ok(ret);
                    }
                }

                // If there are no data fields, allow
                if (req.data.is_none() || req.data.as_ref().unwrap().is_empty())
                    && (req.body.is_none() || req.body.as_ref().unwrap().is_empty())
                {
                    ret.allowed = true;
                    return Ok(ret);
                }

                if self.denied_parameters.get("*").is_some() {
                    return Ok(ret);
                }

                for (denied_key, denied_value) in self.denied_parameters.iter() {
                    if let Ok(param) = req.get_data(denied_key.to_lowercase().as_str()) {
                        let denied_array = denied_value.as_array().unwrap();
                        if denied_array.contains(&param) {
                            return Ok(ret);
                        }
                    }
                }

                let allowed_all = self.allowed_parameters.get("*").is_some();

                if self.allowed_parameters.is_empty() || (allowed_all && self.allowed_parameters.len() == 1) {
                    ret.allowed = true;
                    return Ok(ret);
                }

                for (param_key, param_value) in req.data_iter() {
                    if let Some(allowed_param) = self.allowed_parameters.get(param_key.to_lowercase().as_str()) {
                        let allowed_array = allowed_param.as_array().unwrap();
                        if !allowed_array.contains(param_value) {
                            return Ok(ret);
                        }
                    } else if !allowed_all {
                        return Ok(ret);
                    }
                }
            }
            _ => {}
        }

        ret.allowed = true;

        Ok(ret)
    }

    pub fn merge(&mut self, other: &Permissions) -> Result<(), RvError> {
        let deny = Capability::Deny.to_bits();
        if self.capabilities_bitmap & deny != 0 {
            // If we are explicitly denied in the existing capability set, don't save anything else
            return Ok(());
        }
        if other.capabilities_bitmap & deny != 0 {
            // If this new policy explicitly denies, only save the deny value
            self.capabilities_bitmap = deny;
            self.allowed_parameters.clear();
            self.denied_parameters.clear();
            return Ok(());
        }

        self.capabilities_bitmap |= other.capabilities_bitmap;

        let zero_ttl = Duration::from_secs(0);

        // If we have an existing max, and we either don't have a current max, or the current is
        // greater than the previous, use the existing.
        if other.max_wrapping_ttl > zero_ttl
            && (self.max_wrapping_ttl == zero_ttl || self.max_wrapping_ttl < other.max_wrapping_ttl)
        {
            self.max_wrapping_ttl = other.max_wrapping_ttl;
        }

        // If we have an existing min, and we either don't have a current min, or the current is
        // greater than the previous, use the existing
        if other.min_wrapping_ttl > zero_ttl
            && (self.min_wrapping_ttl == zero_ttl || self.min_wrapping_ttl < other.min_wrapping_ttl)
        {
            self.min_wrapping_ttl = other.min_wrapping_ttl;
        }

        if !other.allowed_parameters.is_empty() {
            serde_map_merge(&mut self.allowed_parameters, &other.allowed_parameters);
        }

        if !other.denied_parameters.is_empty() {
            serde_map_merge(&mut self.denied_parameters, &other.denied_parameters);
        }

        if !other.required_parameters.is_empty() {
            for param in other.required_parameters.iter() {
                if !self.required_parameters.contains(param) {
                    self.required_parameters.push(param.clone());
                }
            }
        }

        Ok(())
    }

    pub fn add_granting_policy_to_map(&mut self, policy: &Policy) -> Result<(), RvError> {
        for cap in Capability::iter() {
            if cap.to_bits() & self.capabilities_bitmap == 0 {
                continue;
            }

            let pi = PolicyInfo { name: policy.name.clone(), policy_type: "acl".into(), ..Default::default() };

            self.granting_policies_map.entry(cap.to_bits()).or_insert_with(Vec::new).push(pi);
        }

        Ok(())
    }

    pub fn get_granting_capabilities(&self) -> Vec<String> {
        to_granting_capabilities(self.capabilities_bitmap)
    }
}

pub fn to_granting_capabilities(value: u32) -> Vec<String> {
    let mut ret = Vec::new();
    let deny = Capability::Deny;
    if value & deny.to_bits() != 0 {
        ret.push(deny.to_string());
        return ret;
    }

    for cap in Capability::iter() {
        if cap.to_bits() & value != 0 {
            ret.push(cap.to_string());
        }
    }

    ret
}

pub fn serde_map_merge(dst: &mut Map<String, Value>, src: &Map<String, Value>) {
    if dst.is_empty() {
        *dst = src.clone();
    } else {
        for (key, value) in src.iter() {
            let value_is_empty = value.as_array().map_or(false, |v| v.is_empty());
            let existing = dst.get(key.as_str());
            let existing_is_empty = existing.map_or(false, |x| x.as_array().map_or(false, |v| v.is_empty()));

            if value_is_empty || existing_is_empty {
                dst.remove(key.as_str());
            } else {
                let mut new_arr = value.as_array().unwrap_or(&Vec::new()).clone();
                let existing_arr: Vec<Value> =
                    existing.map_or(Vec::new(), |x| x.as_array().map_or(Vec::new(), |v| v.clone()));
                new_arr.extend(existing_arr);
                dst.insert(key.clone(), Value::Array(new_arr));
            }
        }
    }
}
