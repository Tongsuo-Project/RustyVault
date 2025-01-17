use std::collections::HashMap;

use better_default::Default;
use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

use super::lease::Lease;

#[derive(Debug, Clone, Default, Serialize, Deserialize, Deref, DerefMut)]
pub struct Auth {
    #[deref]
    #[deref_mut]
    pub lease: Lease,

    // ClientToken is the token that is generated for the authentication.
    // This will be filled in by Vault core when an auth structure is returned.
    // Setting this manually will have no effect.
    pub client_token: String,

    // DisplayName is a non-security sensitive identifier that is applicable to this Auth.
    // It is used for logging and prefixing of dynamic secrets. For example,
    // DisplayName may be "armon" for the github credential backend. If the client token
    // is used to generate a SQL credential, the user may be "github-armon-uuid".
    // This is to help identify the source without using audit tables.
    pub display_name: String,

    // Policies is the list of policies that the authenticated user is associated with.
    pub policies: Vec<String>,

    // token_policies break down the list in policies to help determine where a policy was sourced
    #[serde(default)]
    pub token_policies: Vec<String>,

    // Indicates that the default policy should not be added by core when creating a token.
    // The default policy will still be added if it's explicitly defined.
    pub no_default_policy: bool,

    // InternalData is JSON-encodable data that is stored with the auth struct.
    // This will be sent back during a Renew/Revoke for storing internal data used for those operations.
    pub internal_data: HashMap<String, String>,

    // Metadata is used to attach arbitrary string-type metadata to an authenticated user.
    // This metadata will be outputted into the audit log.
    pub metadata: HashMap<String, String>,

    // policy_results is the set of policies that grant the token access to the requesting path.
    pub policy_results: Option<PolicyResults>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyResults {
    pub allowed: bool,
    pub granting_policies: Vec<PolicyInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub name: String,
    pub namespace_id: String,
    pub namespace_path: String,
    #[serde(rename = "type")]
    #[default("acl".into())]
    pub policy_type: String,
}
