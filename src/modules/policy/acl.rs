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

#[derive(Debug, Clone, Default)]
pub struct AuthResults {
    pub acl_results: ACLResults,
    pub sentinel_results: SentinelResults,
    pub allowed: bool,
    pub root_privs: bool,
    pub denied_error: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ACLResults {
    pub allowed: bool,
    pub root_privs: bool,
    pub is_root: bool,
    pub capabilities_bitmap: u32,
    pub granting_policies: Vec<PolicyInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct SentinelResults {
    pub granting_policies: Vec<PolicyInfo>,
}

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
        Err(RvError::ErrUnknown)
    }

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

    pub fn insert_permissions(&mut self, pr: &PolicyPathRules, perm: Permissions) -> Result<(), RvError> {
        if pr.has_segment_wildcards {
            self.segment_wildcard_paths.insert(pr.path.clone(), perm);
        } else {
            let tree = if pr.is_prefix { &mut self.prefix_rules } else { &mut self.exact_rules };

            tree.insert(pr.path.clone(), perm);
        }

        Ok(())
    }

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
