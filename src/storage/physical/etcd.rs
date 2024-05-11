use super::{Backend, BackendEntry};
use crate::errors::RvError;
use crate::storage::physical::error::BackendError::EtcdError;
use anyhow::Ok;
use etcd_client::*;
use serde_json::Value;
use std::{collections::HashMap, env, time::Duration};

pub const ETCD_BACKEND_PATH: &str = "/rusty_vault";

pub struct EtcdBackend {
    path: Vec<String>,
    endpoints: Vec<String>,
    options: ConnectOptions,
}

/// Implementation of the `Backend` trait for the Etcd backend.
impl Backend for EtcdBackend {
    /// Retrieves a list of keys with the specified prefix from the Etcd backend.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix used to filter the keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use rusty_vault::storage::Backend;
    /// use rusty_vault::error::RvError;
    ///
    /// let etcd_backend = EtcdBackend::new();
    /// let keys = etcd_backend.list("prefix");
    /// match keys {
    ///     Ok(keys) => {
    ///         for key in keys {
    ///             println!("{}", key);
    ///         }
    ///     },
    ///     Err(error) => {
    ///         eprintln!("Error: {}", error);
    ///     }
    /// }
    /// ```
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        // Implementation details...
        let mut path = self.path.clone();
        let rt = tokio::runtime::Handle::current();
        if !prefix.is_empty() {
            path.push(prefix.to_string());
        }

        let _ = rt
            .block_on(async {
                let mut client = Client::connect(self.endpoints.clone(), Some(self.options.clone())).await?;
                client.get(path.join("/"), Some(GetOptions::new().with_prefix().with_keys_only())).await
            })
            .map_err(|_error| RvError::BackendError { source: EtcdError("request error".to_string()) })
            .map(|resp| {
                let mut ks = vec![];
                for kv in resp.kvs() {
                    ks.push(kv.key_str().unwrap().to_string());
                }
                Ok(ks)
            })?;
        Err(RvError::BackendError { source: EtcdError(format!("list key {} error", path.join("/"))) })
    }

    /// Retrieves the value associated with the specified key from the Etcd backend.
    ///
    /// # Arguments
    ///
    /// * `key` - The key used to retrieve the value.
    ///
    /// # Examples
    ///
    /// ```
    /// use rusty_vault::storage::Backend;
    /// use rusty_vault::error::RvError;
    ///
    /// let etcd_backend = EtcdBackend::new();
    /// let entry = etcd_backend.get("key");
    /// match entry {
    ///     Ok(Some(backend_entry)) => {
    ///         println!("Value: {:?}", backend_entry.value);
    ///     },
    ///     Ok(None) => {
    ///         println!("Key not found");
    ///     },
    ///     Err(error) => {
    ///         eprintln!("Error: {}", error);
    ///     }
    /// }
    /// ```
    fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        // Implementation details...
        let mut path = self.path.clone();
        let rt = tokio::runtime::Handle::current();

        path.push(key.to_string());
        println!("{:?}", path.join("/"));

        let _ = rt
            .block_on(async {
                let mut client = Client::connect(self.endpoints.clone(), Some(self.options.clone())).await?;
                client.get(path.join("/"), None).await
            })
            .map_err(|_error| RvError::BackendError { source: EtcdError("request error".to_string()) })
            .map(|resp| {
                if let Some(kv) = resp.kvs().first() {
                    Ok(Some(BackendEntry { key: kv.key_str().unwrap().to_string(), value: kv.value().to_vec() }))
                } else {
                    Ok(None)
                }
            })?;
        Err(RvError::BackendError { source: EtcdError(format!("get key {} error", path.join("/"))) })
    }

    /// Stores the specified key-value pair in the Etcd backend.
    ///
    /// # Arguments
    ///
    /// * `entry` - The key-value pair to store.
    ///
    /// # Examples
    ///
    /// ```
    /// use rusty_vault::storage::Backend;
    /// use rusty_vault::error::RvError;
    ///
    /// let etcd_backend = EtcdBackend::new();
    /// let backend_entry = BackendEntry::new("key", vec![1, 2, 3]);
    /// let result = etcd_backend.put(&backend_entry);
    /// match result {
    ///     Ok(()) => {
    ///         println!("Key-value pair stored successfully");
    ///     },
    ///     Err(error) => {
    ///         eprintln!("Error: {}", error);
    ///     }
    /// }
    /// ```
    fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        // Implementation details...
        let mut path = self.path.clone();
        let rt = tokio::runtime::Handle::current();

        path.push(entry.key.to_string());
        rt.block_on(async {
            let mut client = Client::connect(self.endpoints.clone(), Some(self.options.clone())).await?;
            client.put(path.join("/"), entry.value.clone(), None).await
        })
        .map_err(|_error| RvError::BackendError { source: EtcdError("request error".to_string()) })
        .map(|_resp| ())
    }

    /// Deletes the specified key from the Etcd backend.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete.
    ///
    /// # Examples
    ///
    /// ```
    /// use rusty_vault::storage::Backend;
    /// use rusty_vault::error::RvError;
    ///
    /// let etcd_backend = EtcdBackend::new();
    /// let result = etcd_backend.delete("key");
    /// match result {
    ///     Ok(()) => {
    ///         println!("Key deleted successfully");
    ///     },
    ///     Err(error) => {
    ///         eprintln!("Error: {}", error);
    ///     }
    /// }
    /// ```
    fn delete(&self, key: &str) -> Result<(), RvError> {
        // Implementation details...
        let mut path = self.path.clone();
        let rt = tokio::runtime::Handle::current();
        path.push(key.to_string());

        rt.block_on(async {
            let mut client = Client::connect(self.endpoints.clone(), Some(self.options.clone())).await?;
            client.delete(path.join("/"), None).await
        })
        .map_err(|_error| RvError::BackendError { source: EtcdError("request error".to_string()) })
        .map(|_resp| ())
    }
}

/// Implementation of the EtcdBackend struct.
impl EtcdBackend {
    /// Creates a new instance of EtcdBackend.
    ///
    /// # Arguments
    ///
    /// * `conf` - A reference to a HashMap containing configuration values.
    ///
    /// # Returns
    ///
    /// * `Result<Self, RvError>` - A Result containing the initialized EtcdBackend instance or an error.
    pub fn new(conf: &HashMap<String, Value>) -> Result<Self, RvError> {
        // Extract the 'path' configuration value from the HashMap, or use the default value if not present.
        let path = conf
            .get("path")
            .map(|p| {
                let mut p = p.as_str().unwrap().to_string();
                if !p.starts_with('/') {
                    p.insert(0, '/');
                }
                p
            })
            .unwrap_or_else(|| ETCD_BACKEND_PATH.to_string());

        // Extract the 'address' configuration value from the environment variable or the HashMap, or use the default value if not present.
        let address = env::var("ETCD_ADDR").unwrap_or_else(|_| {
            conf.get("address")
                .map(|a| a.as_str().unwrap().to_string())
                .unwrap_or_else(|| "http://127.0.0.1:2379".to_string())
        });

        // Split the address into individual endpoints and collect them into a Vec<String>.
        let endpoints: Vec<String> = address.split(',').map(|s| s.to_string()).collect();

        // Create a new ConnectOptions instance.
        let mut options = ConnectOptions::new();

        // Extract the 'username' configuration value from the environment variable or the HashMap, or use an empty string if not present.
        let username = env::var("ETCD_USERNAME").unwrap_or_else(|_| {
            conf.get("username").map(|u| u.as_str().unwrap().to_string()).unwrap_or("".to_string())
        });

        // Extract the 'password' configuration value from the environment variable or the HashMap, or use an empty string if not present.
        let password = env::var("ETCD_PASSWORD").unwrap_or_else(|_| {
            conf.get("password").map(|p| p.as_str().unwrap().to_string()).unwrap_or("".to_string())
        });

        // Set the username and password in the ConnectOptions if they are not empty.
        if !username.is_empty() || !password.is_empty() {
            options = options.with_user(&username, &password);
        }

        // Extract the 'request_timeout' configuration value from the HashMap, or use the default value if not present.
        let request_timeout = conf.get("request_timeout").map(|t| t.as_i64().unwrap() as i32).unwrap_or(1);

        // Set the request timeout in the ConnectOptions.
        options = options.with_timeout(Duration::from_secs(request_timeout as u64));

        // Extract the 'tls' configuration value from the HashMap, if present.
        if let Some(tls) = conf.get("tls") {
            // Extract the 'tls_ca_file' configuration value from the 'tls' HashMap, if present.
            let ca_file = tls.get("tls_ca_file").map(|c| c.as_str().unwrap().to_string());

            // If 'tls_ca_file' is present, read the certificate from the file and set it in the ConnectOptions.
            if let Some(ca_file) = ca_file {
                let cert = Certificate::from_pem(&std::fs::read(ca_file.as_str()).unwrap());
                let tls_options = TlsOptions::new().ca_certificate(cert);
                options = options.with_tls(tls_options);
            }
        }

        // Create a new instance of the Etcd client.
        Ok(EtcdBackend { path: path.split('/').map(String::from).collect(), endpoints, options })
            .map_err(|error| RvError::BackendError { source: EtcdError(format!("connect etcd error: {}", error)) })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::{
        super::test::{test_backend, test_backend_list_prefix},
        *,
    };

    #[test]
    fn test_etcd_backend() {
        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String("/rusty_vault".to_string()));
        conf.insert("address".to_string(), Value::String("http://127.0.0.1:2379".to_string()));
        let backend = EtcdBackend::new(&conf);

        assert!(backend.is_ok());

        let backend = backend.unwrap();

        test_backend(&backend);
        test_backend_list_prefix(&backend);
    }
}
