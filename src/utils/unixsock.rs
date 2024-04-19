use std::fmt;
use as_any::Downcast;
use serde::{Deserialize, Serialize};

use super::{
    sockaddr::{SockAddr, SockAddrType},
};

use crate::errors::RvError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnixSock {
    pub path: String,
}

impl UnixSock {
    pub fn new(s: &str) -> Result<Self, RvError> {
        Ok(Self {
            path: s.to_string(),
        })
    }
}

impl SockAddr for UnixSock {
    fn contains(&self, other: &dyn SockAddr) -> bool {
        if let Some(unix_sock) = other.downcast_ref::<UnixSock>() {
            return self.path == unix_sock.path;
        }

        false
    }

    fn equal(&self, other: &dyn SockAddr) -> bool {
        if let Some(unix_sock) = other.downcast_ref::<UnixSock>() {
            return self.path == unix_sock.path;
        }

        false
    }

    fn sock_addr_type(&self) -> SockAddrType {
        SockAddrType::Unix
    }
}

impl fmt::Display for UnixSock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)
    }
}

