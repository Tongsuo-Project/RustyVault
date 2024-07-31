use std::{
    collections::HashMap,
};

use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};

use super::lease::Lease;

#[derive(Debug, Clone, Default, Serialize, Deserialize, Deref, DerefMut)]
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
