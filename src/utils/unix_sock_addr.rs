//! This module is a Rust replica of
//! <https://github.com/hashicorp/go-sockaddr/blob/master/unixsock.go>

use std::fmt;
use as_any::Downcast;
use serde::{Deserialize, Serialize};

use super::{
    sock_addr::{SockAddr, SockAddrType},
};

use crate::errors::RvError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnixSockAddr {
    pub path: String,
}

impl UnixSockAddr {
    pub fn new(s: &str) -> Result<Self, RvError> {
        Ok(Self {
            path: s.to_string(),
        })
    }
}

impl SockAddr for UnixSockAddr {
    fn contains(&self, other: &dyn SockAddr) -> bool {
        if let Some(unix_sock) = other.downcast_ref::<UnixSockAddr>() {
            return self.path == unix_sock.path;
        }

        false
    }

    fn equal(&self, other: &dyn SockAddr) -> bool {
        if let Some(unix_sock) = other.downcast_ref::<UnixSockAddr>() {
            return self.path == unix_sock.path;
        }

        false
    }

    fn sock_addr_type(&self) -> SockAddrType {
        SockAddrType::Unix
    }
}

impl fmt::Display for UnixSockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)
    }
}

#[cfg(test)]
mod test {
    use super::{
        *, super::sock_addr::{SockAddrType},
    };

    #[test]
    fn test_unix_sock_addr() {
        let addr1 = UnixSockAddr::new("/tmp/bar").unwrap();
        let addr2 = UnixSockAddr::new("/tmp/bar").unwrap();
        let addr3 = UnixSockAddr::new("/tmp/foo").unwrap();

        assert!(addr1.contains(&addr2));
        assert!(addr1.equal(&addr2));
        assert!(!addr1.contains(&addr3));
        assert!(!addr1.equal(&addr3));
        assert_eq!(addr1.sock_addr_type(), SockAddrType::Unix);
    }
}
