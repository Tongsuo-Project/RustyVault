//! This Rust file defines the implementation of Access Control Lists (ACLs) for handling
//! authorization and permissions within a security context.
//!
//! The primary structures include:
//! - `AuthResults`: Stores the results of authentication checks, including ACL and sentinel results.
//! - `ACLResults`: Contains detailed results from ACL checks, such as permissions and capabilities.
//! - `SentinelResults`: Holds information about granting policies determined by sentinels.
//! - `ACL`: Manages rules and policies related to access control, using data structures like `Trie`
//!    and `DashMap` for efficient storage and retrieval.
//!
//! Key Functionality:
//! - Constructing an ACL from a list of policies.
//! - Checking if a requested operation is allowed based on the defined ACL rules.
//! - Managing permission rules with support for exact, prefix, and segment wildcard path matching.
//! - Storing and retrieving permissions with efficiency using data structures optimized for this purpose.
//!
//! External Dependencies:
//! - Uses `radix_trie` for efficient storage and retrieval of path rules.
//! - Relies on `dashmap` for concurrent access to wildcard path permissions.

use std::sync::Arc;

use better_default::Default;
use dashmap::DashMap;
use radix_trie::{Trie, TrieCommon};

use super::{policy::Capability, Permissions, Policy, PolicyPathRules, PolicyType};
use crate::{
    errors::RvError,
    logical::{auth::PolicyInfo, Operation, Request},
    rv_error_string,
    utils::string::ensure_no_leading_slash,
};

/// Stores the results of an authentication check, including ACL and sentinel results.
#[derive(Debug, Clone, Default)]
pub struct AuthResults {
    pub acl_results: ACLResults,
    pub sentinel_results: SentinelResults,
    pub allowed: bool,
    pub root_privs: bool,
    pub denied_error: bool,
}

/// Contains the outcome of an ACL check, including capabilities and granting policies.
#[derive(Debug, Clone, Default)]
pub struct ACLResults {
    pub allowed: bool,
    pub root_privs: bool,
    pub is_root: bool,
    pub capabilities_bitmap: u32,
    pub granting_policies: Vec<PolicyInfo>,
}

/// Stores results specific to sentinel checks.
#[derive(Debug, Clone, Default)]
pub struct SentinelResults {
    pub granting_policies: Vec<PolicyInfo>,
}

/// Represents an ACL system, containing rules for exact matches, prefixes, and segment wildcards.
#[derive(Debug, Clone, Default)]
pub struct ACL {
    pub exact_rules: Trie<String, Permissions>,
    pub prefix_rules: Trie<String, Permissions>,
    pub segment_wildcard_paths: DashMap<String, Permissions>,
    pub rgp_policies: Vec<Arc<Policy>>,
    #[default(false)]
    pub root: bool,
}

impl ACL {
    /// Constructs a new `ACL` from a slice of policies.
    ///
    /// This method processes each policy, checking for `Rgp` and `Acl` types. It inserts rules into
    /// appropriate structures based on the path rules, managing exact matches, prefixes, and segment wildcards.
    ///
    /// # Arguments
    ///
    /// * `policies` - A slice of shared policies to initialize the ACL with.
    ///
    /// # Returns
    ///
    /// * `Result<Self, RvError>` - Returns an initialized `ACL` or an error if a policy type is incorrect.
    pub fn new(policies: &[Arc<Policy>]) -> Result<Self, RvError> {
        let mut acl = ACL::default();
        for policy in policies.iter() {
            if policy.policy_type == PolicyType::Rgp {
                acl.rgp_policies.push(policy.clone());
                continue;
            } else if policy.policy_type != PolicyType::Acl {
                return Err(rv_error_string!("unable to parse policy (wrong type)"));
            }

            if policy.name == "root" {
                if policies.len() != 1 {
                    return Err(rv_error_string!("other policies present along with root"));
                }
                acl.root = true;
            }

            for pr in policy.paths.iter() {
                if let Some(mut existing_perms) = acl.get_permissions(pr)? {
                    let deny = Capability::Deny.to_bits();
                    if existing_perms.capabilities_bitmap & deny != 0 {
                        // If we are explicitly denied in the existing capability set, don't save anything else
                        continue;
                    }

                    existing_perms.merge(&pr.permissions)?;
                    existing_perms.add_granting_policy_to_map(policy)?;
                    acl.insert_permissions(pr, existing_perms)?;
                } else {
                    let mut cloned_perms = pr.permissions.clone();
                    cloned_perms.add_granting_policy_to_map(policy)?;
                    acl.insert_permissions(pr, cloned_perms)?;
                }
            }
        }

        Ok(acl)
    }

    /// Retrieves permissions for a given path rule.
    ///
    /// This method checks for both segment wildcard paths and exact/prefix rules, returning the permissions
    /// if they exist for the given path.
    ///
    /// # Arguments
    ///
    /// * `pr` - A reference to a `PolicyPathRules` to find permissions for.
    ///
    /// # Returns
    ///
    /// * `Result<Option<Permissions>, RvError>` - Returns the permissions if found, otherwise `None`.
    pub fn get_permissions(&self, pr: &PolicyPathRules) -> Result<Option<Permissions>, RvError> {
        if pr.has_segment_wildcards {
            if let Some(existing_perms) = self.segment_wildcard_paths.get(&pr.path) {
                return Ok(Some(existing_perms.value().clone()));
            }
        } else {
            let tree = if pr.is_prefix { &self.prefix_rules } else { &self.exact_rules };

            if let Some(existing_perms) = tree.get(&pr.path) {
                return Ok(Some(existing_perms.clone()));
            }
        }

        Ok(None)
    }

    /// Inserts permissions into the appropriate rule set based on path rules.
    ///
    /// Depending on whether the path uses segment wildcards or is an exact/prefix rule, it inserts the
    /// permissions into the respective storage structure.
    ///
    /// # Arguments
    ///
    /// * `pr` - A reference to `PolicyPathRules` providing path info.
    /// * `perm` - The `Permissions` to insert.
    ///
    /// # Returns
    ///
    /// * `Result<(), RvError>` - Returns an error if insertion fails.
    pub fn insert_permissions(&mut self, pr: &PolicyPathRules, perm: Permissions) -> Result<(), RvError> {
        if pr.has_segment_wildcards {
            self.segment_wildcard_paths.insert(pr.path.clone(), perm);
        } else {
            let tree = if pr.is_prefix { &mut self.prefix_rules } else { &mut self.exact_rules };

            tree.insert(pr.path.clone(), perm);
        }

        Ok(())
    }

    /// Checks if an operation is allowed based on the ACL rules.
    ///
    /// This function checks various rules (exact matches, lists, prefixes, and wildcards) to determine
    /// if the operation specified in the request is allowed.
    ///
    /// # Arguments
    ///
    /// * `req` - A reference to the `Request` being checked.
    /// * `check_only` - A boolean indicating if the function should only perform a check without modifying state.
    ///
    /// # Returns
    ///
    /// * `Result<ACLResults, RvError>` - The result of the ACL check, indicating allowed operations and other details.
    pub fn allow_operation(&self, req: &Request, check_only: bool) -> Result<ACLResults, RvError> {
        if self.root {
            return Ok(ACLResults {
                allowed: true,
                root_privs: true,
                is_root: true,
                granting_policies: vec![PolicyInfo {
                    name: "root".into(),
                    namespace_id: "root".into(),
                    policy_type: "acl".into(),
                    ..Default::default()
                }],
                ..Default::default()
            });
        }

        if req.operation == Operation::Help {
            return Ok(ACLResults { allowed: true, ..Default::default() });
        }

        let path = ensure_no_leading_slash(&req.path);

        if let Some(perm) = self.exact_rules.get(&path) {
            return perm.check(req, check_only);
        }

        if req.operation == Operation::List {
            if let Some(perm) = self.exact_rules.get(path.trim_end_matches("/")) {
                return perm.check(req, check_only);
            }
        }

        if let Some(perm) = self.get_none_exact_paths_permissions(&path)? {
            return perm.check(req, check_only);
        }

        Ok(ACLResults::default())
    }

    /// Retrieves permissions for non-exact paths, such as prefixes or wildcards.
    ///
    /// This method searches for permissions based on prefixes and wildcards when an exact match isn't found.
    ///
    ///  # Arguments
    ///
    ///  * `path` - A string slice of the path to find permissions for.
    ///
    ///  # Returns
    ///
    ///  * `Result<Option<Permissions>, RvError>` - Returns permissions if found, otherwise `None`.
    pub fn get_none_exact_paths_permissions(&self, path: &str) -> Result<Option<Permissions>, RvError> {
        if let Some(item) = self.prefix_rules.get_ancestor(path) {
            if self.segment_wildcard_paths.is_empty() {
                return Ok(Some(item.value().unwrap().clone()));
            }
        }

        if self.segment_wildcard_paths.is_empty() {
            return Ok(None);
        }

        let _path_parts: Vec<&str> = path.split('/').collect();

        // TODO

        Ok(None)
    }
}

#[cfg(test)]
mod mod_policy_acl_tests {
    use std::{str::FromStr, sync::Arc};

    use super::*;
    use crate::logical::{Operation, Request};

    fn create_test_policy(name: &str, policy_str: &str) -> Policy {
        let policy: Result<Policy, RvError> = Policy::from_str(policy_str);
        assert!(policy.is_ok());
        let mut policy = policy.unwrap();
        policy.name = name.into();
        return policy;
    }

    #[test]
    fn test_new_acl() {
        let policy1 = create_test_policy(
            "policy1",
            r#"
            path "path1/" {
                capabilities = ["read", "list"]
            }
            "#,
        );

        let policy2 = create_test_policy(
            "policy2",
            r#"
            path "path2/*" {
                capabilities = ["update", "delete"]
            }
            "#,
        );

        let acl = ACL::new(&[Arc::new(policy1), Arc::new(policy2)]).unwrap();

        assert_eq!(acl.root, false);
        assert_eq!(
            acl.exact_rules.get("path1/").unwrap().capabilities_bitmap,
            Capability::Read.to_bits() | Capability::List.to_bits()
        );
        assert_eq!(
            acl.prefix_rules.get_ancestor_value("path2/kk").unwrap().capabilities_bitmap,
            Capability::Update.to_bits() | Capability::Delete.to_bits()
        );
    }

    #[test]
    fn test_get_permissions() {
        let policy1 = create_test_policy(
            "policy1",
            r#"
            path "path1/" {
                capabilities = ["read", "list"]
            }

            path "path2*" {
                capabilities = ["update", "delete"]
            }
            "#,
        );

        let policy2 = create_test_policy(
            "policy2",
            r#"
            path "path2/*" {
                capabilities = ["update", "delete"]
            }
            "#,
        );

        let (policy1, policy2) = (Arc::new(policy1), Arc::new(policy2));

        let acl = ACL::new(&[policy1.clone(), policy2.clone()]).unwrap();

        let perm1 = acl.get_permissions(&policy1.paths[0]).unwrap().unwrap();
        if policy1.paths[0].path == "path1/" {
            assert_eq!(perm1.capabilities_bitmap, Capability::Read.to_bits() | Capability::List.to_bits());
        } else {
            assert_eq!(perm1.capabilities_bitmap, Capability::Update.to_bits() | Capability::Delete.to_bits());
        }

        let perm2 = acl.get_permissions(&policy2.paths[0]).unwrap().unwrap();
        assert_eq!(perm2.capabilities_bitmap, Capability::Update.to_bits() | Capability::Delete.to_bits());
    }

    #[test]
    fn test_insert_permissions() {
        let mut acl = ACL::default();
        let perm = Permissions { capabilities_bitmap: Capability::Read.to_bits(), ..Default::default() };

        acl.insert_permissions(
            &PolicyPathRules {
                path: "path1/".to_string(),
                is_prefix: false,
                has_segment_wildcards: false,
                ..Default::default()
            },
            perm.clone(),
        )
        .unwrap();

        assert_eq!(acl.exact_rules.get("path1/").unwrap().capabilities_bitmap, Capability::Read.to_bits());

        acl.insert_permissions(
            &PolicyPathRules {
                path: "path2".to_string(),
                is_prefix: true,
                has_segment_wildcards: false,
                ..Default::default()
            },
            perm,
        )
        .unwrap();

        assert_eq!(
            acl.prefix_rules.get_ancestor_value("path222").unwrap().capabilities_bitmap,
            Capability::Read.to_bits()
        );
    }

    #[test]
    fn test_allow_operation() {
        let policy1 = create_test_policy(
            "policy1",
            r#"
            path "path1/" {
                capabilities = ["read"]
            }
            "#,
        );

        let acl = ACL::new(&[Arc::new(policy1)]).unwrap();

        let mut req = Request { operation: Operation::Read, path: "path1/".to_string(), ..Default::default() };

        let result = acl.allow_operation(&req, false).unwrap();
        assert!(result.allowed);
        assert!(!result.root_privs);
        assert!(!result.is_root);
        assert_eq!(result.capabilities_bitmap, Capability::Read.to_bits());

        req.path = "path2/".to_string();
        let result = acl.allow_operation(&req, false).unwrap();
        assert!(!result.allowed);
        assert!(!result.root_privs);
        assert!(!result.is_root);
        assert_eq!(result.capabilities_bitmap, 0);
    }

    #[test]
    fn test_get_none_exact_paths_permissions() {
        let policy1 = create_test_policy(
            "policy1",
            r#"
            path "path1/*" {
                capabilities = ["read"]
            }
            "#,
        );

        let acl = ACL::new(&[Arc::new(policy1)]).unwrap();

        let result = acl.get_none_exact_paths_permissions("path1/subpath").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().capabilities_bitmap, Capability::Read.to_bits());
    }
}
