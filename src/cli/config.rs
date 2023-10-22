use std::{
    fs,
    path::Path,
    collections::HashMap,
};
use serde::{Serialize, Deserialize, Deserializer};
use serde_json::{Value};
use crate::{
    errors::RvError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(deserialize_with = "validate_listener")]
    pub listener: HashMap<String, Listener>,
    #[serde(deserialize_with = "validate_storage")]
    pub storage: HashMap<String, Storage>,
    #[serde(default)]
    pub api_addr: String,
    #[serde(default)]
    pub log_format: String,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub pid_file: String,
    #[serde(default)]
    pub work_dir: String,
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub daemon: bool,
    #[serde(default)]
    pub daemon_user: String,
    #[serde(default)]
    pub daemon_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    #[serde(default)]
    pub ltype: String,
    pub address: String,
    #[serde(default, deserialize_with = "parse_bool_string")]
    pub tls_disable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Storage {
    #[serde(default)]
    pub stype: String,
    #[serde(flatten)]
    pub config: HashMap<String, Value>,
}

fn parse_bool_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
D: Deserializer<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;
    match value {
        Value::Bool(b) => Ok(b),
        Value::String(s) => match s.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(serde::de::Error::custom("Invalid value for bool")),
        },
        _ => Err(serde::de::Error::custom("Invalid value for bool")),
    }
}

fn validate_storage<'de, D>(deserializer: D) -> Result<HashMap<String, Storage>, D::Error>
where
D: serde::Deserializer<'de>,
{
    let storage: HashMap<String, Storage> = Deserialize::deserialize(deserializer)?;

    for key in storage.keys() {
        if key != "file" {
            return Err(serde::de::Error::custom("Invalid storage key"));
        }
    }

    Ok(storage)
}

fn validate_listener<'de, D>(deserializer: D) -> Result<HashMap<String, Listener>, D::Error>
where
D: serde::Deserializer<'de>,
{
    let listener: HashMap<String, Listener> = Deserialize::deserialize(deserializer)?;

    for key in listener.keys() {
        if key != "tcp" {
            return Err(serde::de::Error::custom("Invalid listener key"));
        }
    }

    Ok(listener)
}

impl Config {
    pub fn merge(&mut self, other: Config) {
        self.listener.extend(other.listener);
        self.storage.extend(other.storage);
        if other.api_addr != "" {
            self.api_addr = other.api_addr;
        }

        if other.log_format != "" {
            self.log_format = other.log_format;
        }

        if other.log_level != "" {
            self.log_level = other.log_level;
        }

        if other.pid_file != "" {
            self.pid_file = other.pid_file;
        }
    }
}

pub fn load_config(path: &str) -> Result<Config, RvError> {
    let f = Path::new(path);
    if f.is_dir() {
        load_config_dir(path)
    } else if f.is_file() {
        load_config_file(path)
    } else {
        Err(RvError::ErrConfigPathInvalid)
    }
}

fn load_config_dir(dir: &str) -> Result<Config, RvError> {
    log::debug!("load_config_dir: {}", dir);
    let mut paths: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                if let Some(ext) = path.extension() {
                    if ext == "hcl" || ext == "json" {
                        let filename = path.to_string_lossy().into_owned();
                        paths.push(filename);
                    }
                }
            }
        }
    }

    let mut result = None;

    for path in paths {
        log::debug!("load_config_dir path: {}", path);
        let config = load_config_file(&path)?;
        if result.is_none() {
            result = Some(config.clone());
        } else {
            result.as_mut().unwrap().merge(config);
        }
    }

    result.ok_or(RvError::ErrConfigLoadFailed)
}

fn load_config_file(path: &str) -> Result<Config, RvError> {
    log::debug!("load_config_file: {}", path);
    let file = fs::File::open(path)?;

    if path.ends_with(".hcl") {
        let mut config: Config = hcl::from_reader(file)?;
        set_config_type_field(&mut config)?;
        Ok(config)
    } else if path.ends_with(".json") {
        let mut config: Config = serde_json::from_reader(file)?;
        set_config_type_field(&mut config)?;
        Ok(config)
    } else {
        return Err(RvError::ErrConfigPathInvalid);
    }
}

fn set_config_type_field(config: &mut Config) -> Result<(), RvError> {
    config.storage.iter_mut().for_each(|(key, value)| value.stype = key.clone());
    config.listener.iter_mut().for_each(|(key, value)| value.ltype = key.clone());
    Ok(())
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::io::prelude::*;
    use go_defer::defer;
    use super::*;

    fn write_file(path: &str, config: &str) -> Result<(), RvError> {
        let mut file = fs::File::create(path)?;

        file.write_all(config.as_bytes())?;

        file.flush()?;

        Ok(())
    }

    #[test]
    fn test_load_config() {
        let dir = env::temp_dir().join("rusty_vault_config_test");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
            );

        let file_path = dir.join("config.hcl");
        let path = file_path.to_str().unwrap_or("config.hcl");

        let hcl_config = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
            }

            api_addr = "http://127.0.0.1:8200"
            log_level = "debug"
            log_format = "{date} {req.path}"
            pid_file = "/tmp/rusty_vault.pid"
        "#;

            assert!(write_file(path, hcl_config).is_ok());

            let config = load_config(path);
            assert!(config.is_ok());
            let hcl_config = config.unwrap();
            println!("hcl config: {:?}", hcl_config);

            let json_config = r#"{
            "storage": {
                "file": {
                    "path": "./vault/data"
                }
            },
            "listener": {
                "tcp": {
                    "address": "127.0.0.1:8200"
                }
            },
            "api_addr": "http://127.0.0.1:8200",
            "log_level": "debug",
            "log_format": "{date} {req.path}",
            "pid_file": "/tmp/rusty_vault.pid"
        }"#;

            let file_path = dir.join("config.json");
            let path = file_path.to_str().unwrap_or("config.json");
            assert!(write_file(path, json_config).is_ok());

            let config = load_config(path);
            assert!(config.is_ok());
            let json_config = config.unwrap();
            println!("json config: {:?}", json_config);

            let hcl_config_value = serde_json::to_value(&hcl_config);
            assert!(hcl_config_value.is_ok());
            let hcl_config_value: Value = hcl_config_value.unwrap();

            let json_config_value = serde_json::to_value(&json_config);
            assert!(json_config_value.is_ok());
            let json_config_value: Value = json_config_value.unwrap();
            assert_eq!(hcl_config_value, json_config_value);
    }

    #[test]
    fn test_load_config_dir() {
        let dir = env::temp_dir().join("rusty_vault_config_dir_test");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
            );

        let file_path = dir.join("config1.hcl");
        let path = file_path.to_str().unwrap_or("config1.hcl");

        let hcl_config = r#"
            storage "file" {
              path    = "./vault/data"
            }

            listener "tcp" {
              address     = "127.0.0.1:8200"
              tls_disable = "false"
            }

            api_addr = "http://127.0.0.1:8200"
            log_level = "debug"
            log_format = "{date} {req.path}"
            pid_file = "/tmp/rusty_vault.pid"
        "#;

            assert!(write_file(path, hcl_config).is_ok());

            let file_path = dir.join("config2.hcl");
            let path = file_path.to_str().unwrap_or("config2.hcl");

            let hcl_config = r#"
            storage "file" {
              address    = "127.0.0.1:8899"
            }

            listener "tcp" {
              address     = "127.0.0.1:8800"
              tls_disable = true
            }

            log_level = "info"
        "#;

            assert!(write_file(path, hcl_config).is_ok());

            let config = load_config(dir.to_str().unwrap());
            assert!(config.is_ok());
            let hcl_config = config.unwrap();
            println!("hcl config: {:?}", hcl_config);
    }
}
