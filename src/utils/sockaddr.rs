use std::{
    fmt,
    str::FromStr,
};

use as_any::AsAny;
use serde::{Deserialize, Serialize};

use super::{
    ipaddr::IpAddr,
};

use crate::errors::RvError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SockAddrType {
    Unknown = 0x0,
    Unix = 0x1,
    IPv4 = 0x2,
    IPv6 = 0x4,
    // IP is the union of IPv4 and IPv6
    IP = 0x6,
}

pub trait SockAddr: fmt::Display + AsAny {
    // contains returns true if the other SockAddr is contained within the receiver
    fn contains(&self, other: &dyn SockAddr) -> bool;

    // equal allows for the comparison of two SockAddrs
    fn equal(&self, other: &dyn SockAddr) -> bool;

    fn sock_addr_type(&self) -> SockAddrType;
}

pub struct SockAddrMarshaler {
    pub sock_addr: Box<dyn SockAddr>,
}

impl SockAddrMarshaler {
    pub fn new(sock_addr: Box<dyn SockAddr>) -> Self {
        SockAddrMarshaler { sock_addr }
    }
}

impl fmt::Display for SockAddrMarshaler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sock_addr)
    }
}

impl fmt::Display for SockAddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = match self {
            SockAddrType::IPv4 => "IPv4",
            SockAddrType::IPv6 => "IPv6",
            SockAddrType::Unix => "Unix",
            _ => "Unknown",
        };
        write!(f, "{}", type_str)
    }
}

impl FromStr for SockAddrType {
    type Err = RvError;
    fn from_str(s: &str) -> Result<Self, RvError> {
        match s {
            "IPv4" | "ipv4" => Ok(SockAddrType::IPv4),
            "IPv6" | "ipv6" => Ok(SockAddrType::IPv6),
            "Unix" | "UNIX" | "unix" => Ok(SockAddrType::Unix),
            _ => Err(RvError::ErrResponse("invalid sockaddr type".to_string()))
        }
    }
}

pub fn new_sock_addr(s: &str) -> Result<Box<dyn SockAddr>, RvError> {
    let ret = IpAddr::new(s)?;
    Ok(Box::new(ret))
}
