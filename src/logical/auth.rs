use std::{
    collections::HashMap,
};

use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

use super::lease::Lease;

#[derive(Debug, Clone, Serialize, Deserialize, Deref, DerefMut)]
pub struct Auth {
    #[deref]
    #[deref_mut]
    pub lease: Lease,
    pub client_token: String,
    pub display_name: String,
    pub policies: Vec<String>,
    pub internal_data: HashMap<String, String>,
    pub metadata: HashMap<String, String>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            lease: Lease::default(),
            client_token: String::new(),
            display_name: String::new(),
            policies: Vec::new(),
            internal_data: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
}
