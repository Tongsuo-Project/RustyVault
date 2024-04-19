use std::{
    fmt,
    str::FromStr,
    net::SocketAddr,
};

use as_any::Downcast;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use super::{
    sockaddr::{SockAddr, SockAddrType},
};

use crate::errors::RvError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpAddr {
    pub addr: IpNetwork,
    pub port: u16,
}

impl IpAddr {
    pub fn new(s: &str) -> Result<Self, RvError> {
        if let Ok(sock_addr) = SocketAddr::from_str(s) {
            return Ok(IpAddr {
                addr: IpNetwork::from(sock_addr.ip()),
                port: sock_addr.port(),
            });
        } else if let Ok(ip_addr) = IpNetwork::from_str(s) {
            return Ok(IpAddr {
                addr: ip_addr,
                port: 0,
            });
        }
        return Err(RvError::ErrResponse(format!("Unable to parse {} to an IP address:", s)));
    }
}

impl SockAddr for IpAddr {
    fn contains(&self, other: &dyn SockAddr) -> bool {
        if let Some(ip_addr) = other.downcast_ref::<IpAddr>() {
            return self.addr.contains(ip_addr.addr.ip());
        }

        false
    }

    fn equal(&self, other: &dyn SockAddr) -> bool {
        if let Some(ip_addr) = other.downcast_ref::<IpAddr>() {
            return self.addr == ip_addr.addr && self.port == ip_addr.port;
        }

        false
    }

    fn sock_addr_type(&self) -> SockAddrType {
        match self.addr {
            IpNetwork::V4(_) => SockAddrType::IPv4,
            IpNetwork::V6(_) => SockAddrType::IPv6,
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == 0 {
            write!(f, "{}", self.addr.ip())
        } else {
            write!(f, "{}:{}", self.addr.ip(), self.port)
        }
    }
}

