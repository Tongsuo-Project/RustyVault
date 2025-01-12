//! This file defines structures and implementations for handling security policies.
//!
//! The core components include:
//! - `PolicyType`: An enum representing different types of policies such as ACL, RGP, EGP, and Token.
//! - `Policy`: A struct that represents a security policy, encompassing a name, type, and rules associated with specific paths.
//! - `PolicyPathRules`: A struct that defines rules and permissions for individual paths within a policy.
//! - `Permissions`: A struct managing capabilities and parameter rules for policies, including allowed, denied, and required parameters.
//! - `Capability`: An enum representing various capabilities (e.g., Read, Write, Delete) that can be associated with a policy path.
//!
//! Key functionality:
//! - Parsing policies from strings using the `FromStr` trait, supporting both HCL and JSON formats.
//! - Checking permissions against requests to determine allowed operations.
//! - Merging permissions from multiple sources, ensuring correct precedence and handling of capabilities.
//! - Managing and querying capabilities as bitmaps, converting between bit representations and string lists.
//! - Handling parameter rules, including merging and checking against allowed and denied lists.

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

/// The `Policy` struct holds the main policy details including its rules and configurations.
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

/// Describes rules associated with specific paths in a policy.
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

/// Structure holding permissions and associated configurations.
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

// Configuration struct used to parse policy data from HCL/JSON.
#[derive(Debug, Deserialize)]
struct PolicyConfig {
    pub path: HashMap<String, PolicyPathConfig>,
}

// Path-specific configuration used in policy definitions.
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

/// Enumeration of possible capabilities, supporting string conversion and iteration.
#[derive(Debug, StrumDisplay, Copy, Clone, PartialEq, Eq, EnumString, EnumIter, Deserialize)]
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
    /// Converts a capability to its bit representation.
    pub fn to_bits(&self) -> u32 {
        *self as u32
    }
}

impl FromStr for Policy {
    type Err = RvError;

    /// Parses a string into a Policy struct. The input string can be in either HCL or JSON format.
    /// It constructs a `Policy` object by parsing paths and associated configurations from the input.
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice that holds the representation of the policy configuration.
    ///
    /// # Returns
    ///
    /// * `Ok(Policy)` if parsing succeeds.
    /// * `Err(RvError)` if the input string is malformed or if there are invalid configurations.
    ///
    /// # Errors
    ///
    /// * Returns an error if path contains invalid wildcards (`+*`).
    /// * Returns an error if `allowed_parameters` or `denied_parameters` are not arrays.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use rusty_vault::modules::policy::Policy;
    ///
    /// let policy_str = r#"
    /// {
    ///     "path": {
    ///         "secret/data/*": {
    ///             "capabilities": ["read", "list"],
    ///             "allowed_parameters": {
    ///                 "version": ["1", "2"]
    ///             }
    ///         }
    ///     }
    /// }
    /// "#;
    ///
    /// let policy = Policy::from_str(policy_str);
    /// assert!(policy.is_ok());
    ///
    /// let invalid_policy_str = r#"
    /// {
    ///     "path": {
    ///         "secret/data/+*": { // Invalid path with `+*` wildcard
    ///             "capabilities": ["read"]
    ///         }
    ///     }
    /// }
    /// "#;
    ///
    /// let invalid_policy = Policy::from_str(invalid_policy_str);
    /// assert!(invalid_policy.is_err());
    ///
    /// let policy_str = r#"
    /// path "secret/*" {
    ///     capabilities = ["read", "list"]
    ///     min_wrapping_ttl = "1h"
    ///     max_wrapping_ttl = "24h"
    ///     allowed_parameters = {"key1" = ["value1", "value2"]}
    ///     denied_parameters = {"key2" = ["value3", "value4"]}
    ///     required_parameters = ["param1", "param2"]
    /// }
    /// "#;
    ///
    /// let policy = Policy::from_str(policy_str);
    /// assert!(policy.is_ok());
    /// ```
    fn from_str(s: &str) -> Result<Self, RvError> {
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
    /// Dummy method to input sentinel policy data; currently does nothing.
    pub fn input_sentinel_policy_data(&mut self, _req: &Request) -> Result<(), RvError> {
        Ok(())
    }

    /// Dummy method to add sentinel policy data; currently does nothing.
    pub fn add_sentinel_policy_data(&self, _resp: &Response) -> Result<(), RvError> {
        Ok(())
    }
}

impl Permissions {
    /// Checks the permissions against a request to determine if it is allowed.
    /// Evaluates capabilities, required parameters, and allowed/denied parameters.
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
                    let key = parameter.to_lowercase();
                    if let Some(data) = &req.data {
                        if data.get(key.as_str()).is_some() {
                            continue;
                        }
                    }
                    if let Some(body) = &req.body {
                        if body.get(key.as_str()).is_some() {
                            continue;
                        }
                    }

                    return Ok(ret);
                }

                // If there are no data fields, allow
                if (req.data.is_none() || req.data.as_ref().unwrap().is_empty())
                    && (req.body.is_none() || req.body.as_ref().unwrap().is_empty())
                {
                    ret.capabilities_bitmap = self.capabilities_bitmap;
                    ret.allowed = true;
                    return Ok(ret);
                }

                if self.denied_parameters.get("*").is_some() {
                    return Ok(ret);
                }

                for (param_key, param_value) in req.data_iter() {
                    if let Some(denied_param) = self.denied_parameters.get(param_key.to_lowercase().as_str()) {
                        let denied_array = denied_param.as_array().unwrap();
                        if denied_array.contains(param_value) {
                            return Ok(ret);
                        }
                    }
                }

                let allowed_all = self.allowed_parameters.get("*").is_some();

                if self.allowed_parameters.is_empty() || (allowed_all && self.allowed_parameters.len() == 1) {
                    ret.capabilities_bitmap = self.capabilities_bitmap;
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

        ret.capabilities_bitmap = self.capabilities_bitmap;
        ret.allowed = true;

        Ok(ret)
    }

    /// Merges another set of permissions into the current set.
    /// Ensures that deny capabilities override others and merges parameter rules.
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
            merge_map(&mut self.allowed_parameters, &other.allowed_parameters);
        }

        if !other.denied_parameters.is_empty() {
            merge_map(&mut self.denied_parameters, &other.denied_parameters);
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

/// Converts a bitmask to a vector of capability strings.
///
/// This function takes a 32-bit integer representing a bitmask of capabilities and converts it into
/// a vector of string representations of the enabled capabilities. The capabilities are defined in
/// the `Capability` enum, and each capability has a corresponding bit position.
///
/// # Arguments
///
/// * `value` - A 32-bit integer representing the bitmask of capabilities.
///
/// # Returns
///
/// A vector of strings, where each string is the name of an enabled capability.
///
/// # Examples
///
/// ```
/// use rusty_vault::modules::policy::policy::{Capability, to_granting_capabilities};
///
/// let bitmask = Capability::Read.to_bits() | Capability::Update.to_bits();
/// let capabilities = to_granting_capabilities(bitmask);
/// assert_eq!(capabilities, vec!["read", "update"]);
/// ```
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

/// Merges two `Map<String, Value>` structures.
///
/// This function merges the contents of two `Map<String, Value>` structures. If a key exists in both
/// maps, the values are combined. If a key exists in only one map, it is added to the destination map.
/// If a key's value is an empty array, it is removed from the destination map.
///
/// # Arguments
///
///  * `dst` - The destination map to which the source map will be merged.
///  * `src` - The source map whose contents will be merged into the destination map.
///
/// # Examples
///
/// ```
/// use serde_json::{json, Map, Value};
/// use rusty_vault::modules::policy::policy::merge_map;
///
/// let mut dst: Map<String, Value> = serde_json::Map::new();
/// dst.insert("key1".to_string(), Value::Array(vec![Value::String("a".to_string())]));
/// dst.insert("key2".to_string(), Value::Array(vec![]));
/// dst.insert("key3".to_string(), Value::Array(vec![Value::String("b".to_string())]));
///
/// let mut src: Map<String, Value> = serde_json::Map::new();
/// src.insert("key1".to_string(), Value::Array(vec![Value::String("c".to_string())]));
/// src.insert("key3".to_string(), Value::Array(vec![]));
/// src.insert("key4".to_string(), Value::Array(vec![Value::String("d".to_string())]));
///
/// merge_map(&mut dst, &src);
///
/// assert_eq!(
///     Value::Object(dst),
///     json!({
///         "key1": ["a", "c"],
///         "key2": [],
///         "key4": ["d"]
///     })
/// );
/// ```
pub fn merge_map(dst: &mut Map<String, Value>, src: &Map<String, Value>) {
    if dst.is_empty() {
        *dst = src.clone();
    } else {
        for (key, value) in src.iter() {
            let src_arr = value.as_array().unwrap_or(&Vec::new()).clone();

            if src_arr.is_empty() {
                dst.remove(key.as_str());
                continue;
            }

            let mut new_arr: Vec<Value> = Vec::new();

            if let Some(found) = dst.get(key.as_str()) {
                if let Some(found_arr) = found.as_array() {
                    if found_arr.is_empty() {
                        dst.remove(key.as_str());
                        continue;
                    }
                    new_arr.extend(found_arr.clone());
                }
            }

            new_arr.extend(src_arr);

            dst.insert(key.clone(), Value::Array(new_arr));
        }
    }
}

#[cfg(test)]
mod mod_policy_tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_policy_from_str_hcl() {
        let hcl_policy = r#"
        path "secret/*" {
            capabilities = ["read", "list"]
            min_wrapping_ttl = "1h"
            max_wrapping_ttl = "24h"
            allowed_parameters = {"key1" = ["value1", "value2"]}
            denied_parameters = {"key2" = ["value3", "value4"]}
            required_parameters = ["param1", "param2"]
        }"#;

        let policy: Result<Policy, RvError> = Policy::from_str(hcl_policy);
        assert!(policy.is_ok());

        let policy = policy.unwrap();
        assert_eq!(policy.name, "");
        assert_eq!(policy.raw, hcl_policy);
        assert_eq!(policy.paths.len(), 1);
        assert_eq!(policy.paths[0].path, "secret/");
        assert_eq!(policy.paths[0].is_prefix, true);
        assert_eq!(
            policy.paths[0].permissions.capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits()
        );
        assert_eq!(policy.paths[0].permissions.min_wrapping_ttl, Duration::from_secs(3600));
        assert_eq!(policy.paths[0].permissions.max_wrapping_ttl, Duration::from_secs(86400));
        assert_eq!(policy.paths[0].permissions.allowed_parameters.len(), 1);
        assert_eq!(policy.paths[0].permissions.denied_parameters.len(), 1);
        assert_eq!(policy.paths[0].permissions.required_parameters, vec!["param1", "param2"]);
    }

    #[test]
    fn test_policy_from_str_json() {
        let json_policy = r#"{
            "path": {
                    "secret/*": {
                    "capabilities": ["read", "list"],
                    "min_wrapping_ttl": "1h",
                    "max_wrapping_ttl": "24h",
                    "allowed_parameters": {"key1": ["value1", "value2"]},
                    "denied_parameters": {"key2": ["value3", "value4"]},
                    "required_parameters": ["param1", "param2"]
                }
            }
        }"#;

        let policy: Result<Policy, RvError> = Policy::from_str(json_policy);
        assert!(policy.is_ok());

        let policy = policy.unwrap();
        assert_eq!(policy.name, "");
        assert_eq!(policy.paths.len(), 1);
        assert_eq!(policy.paths[0].path, "secret/");
        assert_eq!(policy.paths[0].is_prefix, true);
        assert_eq!(
            policy.paths[0].permissions.capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits()
        );
        assert_eq!(policy.paths[0].permissions.min_wrapping_ttl, Duration::from_secs(3600));
        assert_eq!(policy.paths[0].permissions.max_wrapping_ttl, Duration::from_secs(86400));
        assert_eq!(policy.paths[0].permissions.allowed_parameters.len(), 1);
        assert_eq!(policy.paths[0].permissions.denied_parameters.len(), 1);
        assert_eq!(policy.paths[0].permissions.required_parameters, vec!["param1", "param2"]);
    }

    #[test]
    fn test_policy_from_str_invalid_wildcards() {
        let invalid_policy = r#"
        path "secret/+*" {
            capabilities = ["read", "list"]
        }"#;

        let policy: Result<Policy, RvError> = Policy::from_str(invalid_policy);
        assert!(policy.is_err());
    }

    #[test]
    fn test_policy_from_str_invalid_allowed_parameters() {
        let invalid_policy = r#"
        path "secret/*" {
            capabilities = ["read", "list"]
            allowed_parameters = {"key1": "value1"}
        }
        "#;

        let policy: Result<Policy, RvError> = Policy::from_str(invalid_policy);
        assert!(policy.is_err());
    }

    #[test]
    fn test_policy_from_str_hcl_with_multi_path() {
        let hcl_policy = r#"
        path "secret/ak1" {
            capabilities = ["read", "list", "create"]
            min_wrapping_ttl = "1h"
            max_wrapping_ttl = "24h"
            allowed_parameters = {
                "key1" = ["value1", "value2"]
                "key2" = ["value2"]
            }
            denied_parameters = {"key2" = ["value3", "value4"]}
        }
        path "secret/ak2" {
            capabilities = ["read", "list", "create", "update"]
            min_wrapping_ttl = "2h"
            max_wrapping_ttl = "24h"
            allowed_parameters = {
                "key1" = ["value1", "value2"]
                "key2" = ["value2"]
            }
            required_parameters = ["param1"]
        }
        path "secret/akn/*" {
            capabilities = ["read", "list", "create", "update", "delete"]
            min_wrapping_ttl = "3h"
            denied_parameters = {
                "key1" = ["value1", "value2"]
                "key2" = ["value2"]
            }
            required_parameters = ["param1", "param2"]
        }"#;

        let policy: Result<Policy, RvError> = Policy::from_str(hcl_policy);
        assert!(policy.is_ok());

        let policy = policy.unwrap();
        assert_eq!(policy.name, "");
        assert_eq!(policy.paths.len(), 3);

        let (mut i, mut j, mut k) = (0, 1, 2);
        for n in 0..3 {
            if policy.paths[n].path == "secret/ak1" {
                i = n;
            }
            if policy.paths[n].path == "secret/ak2" {
                j = n;
            }
            if policy.paths[n].path == "secret/akn/" {
                k = n;
            }
        }

        assert_eq!(policy.paths[i].path, "secret/ak1");
        assert_eq!(policy.paths[i].is_prefix, false);
        assert_eq!(
            policy.paths[i].permissions.capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits() | Capability::Create.to_bits()
        );
        assert_eq!(policy.paths[i].permissions.min_wrapping_ttl, Duration::from_secs(3600));
        assert_eq!(policy.paths[i].permissions.max_wrapping_ttl, Duration::from_secs(86400));
        assert_eq!(policy.paths[i].permissions.allowed_parameters.len(), 2);
        assert_eq!(policy.paths[i].permissions.denied_parameters.len(), 1);
        assert_eq!(policy.paths[i].permissions.required_parameters.len(), 0);
        assert_eq!(policy.paths[i].capabilities, vec![Capability::Read, Capability::List, Capability::Create]);
        assert_eq!(policy.paths[i].has_segment_wildcards, false);

        assert_eq!(policy.paths[j].path, "secret/ak2");
        assert_eq!(policy.paths[j].is_prefix, false);
        assert_eq!(
            policy.paths[j].permissions.capabilities_bitmap,
            Capability::Read.to_bits()
                | Capability::List.to_bits()
                | Capability::Create.to_bits()
                | Capability::Update.to_bits()
        );
        assert_eq!(policy.paths[j].permissions.min_wrapping_ttl, Duration::from_secs(3600 * 2));
        assert_eq!(policy.paths[j].permissions.max_wrapping_ttl, Duration::from_secs(86400));
        assert_eq!(policy.paths[j].permissions.allowed_parameters.len(), 2);
        assert_eq!(policy.paths[j].permissions.denied_parameters.len(), 0);
        assert_eq!(policy.paths[j].permissions.required_parameters, vec!["param1"]);
        assert_eq!(
            policy.paths[j].capabilities,
            vec![Capability::Read, Capability::List, Capability::Create, Capability::Update]
        );
        assert_eq!(policy.paths[j].has_segment_wildcards, false);

        assert_eq!(policy.paths[k].path, "secret/akn/");
        assert_eq!(policy.paths[k].is_prefix, true);
        assert_eq!(
            policy.paths[k].permissions.capabilities_bitmap,
            Capability::Read.to_bits()
                | Capability::List.to_bits()
                | Capability::Create.to_bits()
                | Capability::Update.to_bits()
                | Capability::Delete.to_bits()
        );
        assert_eq!(policy.paths[k].permissions.min_wrapping_ttl, Duration::from_secs(3600 * 3));
        assert_eq!(policy.paths[k].permissions.max_wrapping_ttl, Duration::from_secs(0));
        assert_eq!(policy.paths[k].permissions.allowed_parameters.len(), 0);
        assert_eq!(policy.paths[k].permissions.denied_parameters.len(), 2);
        assert_eq!(policy.paths[k].permissions.required_parameters, vec!["param1", "param2"]);
        assert_eq!(
            policy.paths[k].capabilities,
            vec![Capability::Read, Capability::List, Capability::Create, Capability::Update, Capability::Delete]
        );
        assert_eq!(policy.paths[k].has_segment_wildcards, false);
    }
}
