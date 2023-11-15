use std::{
    ops::{Deref, DerefMut},
    collections::HashMap,
};
use serde::{Serialize, Deserialize};
use super::{lease::Lease};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    pub lease: Lease,
    pub client_token: String,
    pub display_name: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            lease: Lease::default(),
            client_token: String::new(),
            display_name: String::new(),
            policies: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}

impl Deref for Auth {
    type Target = Lease;

    fn deref(&self) -> &Lease {
        &self.lease
    }
}

impl DerefMut for Auth {
    fn deref_mut(&mut self) -> &mut Lease {
        &mut self.lease
    }
}