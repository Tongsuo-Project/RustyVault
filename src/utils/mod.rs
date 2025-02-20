//! Miscellaneous public handy functions are collected here, such as cryptography tools,
//! uuid generator, etc.

use std::time::{Duration, SystemTime};

use chrono::prelude::*;
use humantime::{format_rfc3339, parse_duration, parse_rfc3339};
use openssl::hash::{Hasher, MessageDigest};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Deserializer, Serializer};

use crate::errors::RvError;

pub mod cert;
pub mod cidr;
pub mod crypto;
pub mod ip_sock_addr;
pub mod key;
pub mod kv_builder;
pub mod locks;
pub mod ocsp;
pub mod policy;
pub mod salt;
pub mod sock_addr;
pub mod string;
pub mod token_util;
pub mod unix_sock_addr;

pub fn generate_uuid() -> String {
    let mut buf = [0u8; 16];
    thread_rng().fill(&mut buf);

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0],
        buf[1],
        buf[2],
        buf[3],
        buf[4],
        buf[5],
        buf[6],
        buf[7],
        buf[8],
        buf[9],
        buf[10],
        buf[11],
        buf[12],
        buf[13],
        buf[14],
        buf[15]
    )
}

pub fn is_str_subset<T: PartialEq>(sub: &Vec<T>, superset: &Vec<T>) -> bool {
    sub.iter().all(|item| superset.contains(item))
}

pub fn sha1(data: &[u8]) -> String {
    let mut hasher = Hasher::new(MessageDigest::sha1()).unwrap();
    hasher.update(data).unwrap();
    let result = hasher.finish().unwrap();
    hex::encode(result)
}

pub fn serialize_system_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = format_rfc3339(*time).to_string();
    serializer.serialize_str(&formatted)
}

pub fn deserialize_system_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let input: &str = Deserialize::deserialize(deserializer)?;
    let parsed_time = parse_rfc3339(input).map_err(serde::de::Error::custom)?;
    let system_time: SystemTime = parsed_time;
    Ok(system_time)
}

pub fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let timestamp = duration.as_secs();
    serializer.serialize_i64(timestamp as i64)
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct DurationVisitor;

    impl serde::de::Visitor<'_> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a number or a string with 's' suffix")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Duration::from_secs(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_duration(value).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

pub fn asn1time_to_timestamp(time_str: &str) -> Result<i64, RvError> {
    // Parse the time string
    let dt = NaiveDateTime::parse_from_str(time_str, "%b %e %H:%M:%S %Y %Z")?;

    // Convert to a DateTime object with UTC timezone
    //let dt_utc = DateTime::<Utc>::from_utc(dt, Utc);
    let dt_utc = Utc.from_utc_datetime(&dt);

    // Get the timestamp
    let timestamp = dt_utc.timestamp();

    Ok(timestamp)
}

pub fn hex_encode_with_colon(bytes: &[u8]) -> String {
    let hex_str = hex::encode(bytes);
    let split_hex: Vec<String> =
        hex_str.as_bytes().chunks(2).map(|chunk| String::from_utf8(chunk.to_vec()).unwrap()).collect();

    split_hex.join(":")
}

pub fn is_protect_path(protected: &[&str], paths: &[&str]) -> bool {
    for p in protected.iter() {
        for path in paths.iter() {
            if path.starts_with(p) {
                return true;
            }
        }
    }

    false
}
