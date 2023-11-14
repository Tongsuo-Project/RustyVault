use std::time::SystemTime;
use rand::{Rng, thread_rng};
use openssl::{
    hash::{
        MessageDigest,
        Hasher,
    }
};
use serde::{Serializer, Deserialize, Deserializer};
use humantime::{format_rfc3339, parse_rfc3339};

pub fn generate_uuid() -> String {
    let mut buf = [0u8; 16];
    thread_rng().fill(&mut buf);

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5],
        buf[6], buf[7],
        buf[8], buf[9],
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
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
    let system_time: SystemTime = parsed_time.into();
    Ok(system_time)
}
