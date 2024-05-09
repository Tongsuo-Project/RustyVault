//! This module is a Rust replica of
//! https://github.com/hashicorp/go-sockaddr/blob/master/sockaddr.go

use std::{
    fmt,
    str::FromStr,
};

use as_any::AsAny;
use serde::{Deserialize, Serialize};

use super::{
    ip_sock_addr::IpSockAddr,
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
    let ret = IpSockAddr::new(s)?;
    Ok(Box::new(ret))
}

#[cfg(test)]
mod test {
    use super::{
        *, super::{
            sock_addr::{SockAddrType},
            ip_sock_addr::IpSockAddr,
            unix_sock_addr::UnixSockAddr,
        },
    };

    #[test]
    fn test_sock_addr() {
        let unix_addr1 = UnixSockAddr::new("/tmp/bar").unwrap();
        let unix_addr2 = UnixSockAddr::new("/tmp/bar").unwrap();
        let unix_addr3 = UnixSockAddr::new("/tmp/foo").unwrap();
        let ip_addr1 = IpSockAddr::new("1.1.1.1").unwrap();
        let ip_addr2 = IpSockAddr::new("1.1.1.1").unwrap();
        let ip_addr3 = IpSockAddr::new("2.2.2.2").unwrap();
        let ip_addr4 = IpSockAddr::new("333.333.333.333");
        let ip_addr5 = IpSockAddr::new("1.1.1.1:80").unwrap();
        let ip_addr6 = IpSockAddr::new("1.1.1.1:80").unwrap();
        let ip_addr7 = IpSockAddr::new("1.1.1.1:8080").unwrap();
        let ip_addr8 = IpSockAddr::new("2.2.2.2:80").unwrap();
        let ip_addr9 = IpSockAddr::new("192.168.0.0/16").unwrap();
        let ip_addr10 = IpSockAddr::new("192.168.0.0/24").unwrap();
        let ip_addr11 = IpSockAddr::new("192.168.0.1").unwrap();
        let ip_addr12 = IpSockAddr::new("192.168.1.1").unwrap();

        assert!(unix_addr1.contains(&unix_addr2));
        assert!(unix_addr1.equal(&unix_addr2));
        assert!(!unix_addr1.contains(&unix_addr3));
        assert!(!unix_addr1.equal(&unix_addr3));
        assert_ne!(unix_addr1.sock_addr_type(), ip_addr1.sock_addr_type());

        assert!(ip_addr4.is_err());
        assert!(ip_addr1.contains(&ip_addr2));
        assert!(ip_addr1.equal(&ip_addr2));
        assert!(!ip_addr1.contains(&ip_addr3));
        assert!(!ip_addr1.equal(&ip_addr3));
        assert_eq!(ip_addr1.sock_addr_type(), SockAddrType::IPv4);
        assert_eq!(ip_addr1.sock_addr_type(), ip_addr2.sock_addr_type());
        assert_ne!(ip_addr1.sock_addr_type(), unix_addr2.sock_addr_type());
        assert!(ip_addr5.contains(&ip_addr6));
        assert!(ip_addr5.equal(&ip_addr6));
        assert!(!ip_addr5.equal(&ip_addr7));
        assert!(!ip_addr5.equal(&ip_addr8));
        assert!(ip_addr9.contains(&ip_addr10));
        assert!(ip_addr9.contains(&ip_addr11));
        assert!(ip_addr9.contains(&ip_addr12));
        assert!(!ip_addr9.contains(&ip_addr1));
        assert!(ip_addr10.contains(&ip_addr9));
        assert!(ip_addr10.contains(&ip_addr11));
        assert!(!ip_addr10.contains(&ip_addr12));
        assert!(!ip_addr9.equal(&ip_addr10));
        assert!(!ip_addr9.equal(&ip_addr11));

        assert!(!ip_addr1.contains(&unix_addr1));
        assert!(!ip_addr1.equal(&unix_addr1));
        assert!(!unix_addr1.contains(&ip_addr1));
        assert!(!unix_addr1.equal(&ip_addr1));
    }
}
