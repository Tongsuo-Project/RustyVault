use std::sync::Arc;

use enum_map::Enum;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::errors::RvError;

pub mod auth;
pub mod backend;
pub mod connection;
pub mod field;
pub mod lease;
pub mod path;
pub mod request;
pub mod response;
pub mod secret;

pub use auth::Auth;
pub use backend::LogicalBackend;
pub use field::{Field, FieldType};
pub use lease::Lease;
pub use path::{Path, PathOperation};
pub use request::Request;
pub use response::Response;
pub use secret::{Secret, SecretData};

#[derive(Eq, PartialEq, Copy, Clone, Debug, EnumString, Display, Enum, Serialize, Deserialize)]
pub enum Operation {
    #[strum(to_string = "list")]
    List,
    #[strum(to_string = "read")]
    Read,
    #[strum(to_string = "write")]
    Write,
    #[strum(to_string = "delete")]
    Delete,
    #[strum(to_string = "help")]
    Help,
    #[strum(to_string = "renew")]
    Renew,
    #[strum(to_string = "revoke")]
    Revoke,
    #[strum(to_string = "rollback")]
    Rollback,
}

pub trait Backend: Send + Sync {
    fn init(&mut self) -> Result<(), RvError>;
    fn setup(&self, key: &str) -> Result<(), RvError>;
    fn cleanup(&self) -> Result<(), RvError>;
    fn get_unauth_paths(&self) -> Option<Arc<Vec<String>>>;
    fn get_root_paths(&self) -> Option<Arc<Vec<String>>>;
    fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError>;
    fn secret(&self, key: &str) -> Option<&Arc<secret::Secret>>;
}
