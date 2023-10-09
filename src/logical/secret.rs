use std::collections::HashMap;
use serde_json::Value;
use super::lease::Lease;

#[derive(Debug, Clone)]
pub struct Secret {
    pub lease: Lease,
    pub lease_id: String,
    pub internal_data: HashMap<String, Value>,
}
