use std::{
    collections::HashMap,
    ops::Index,
    sync::{Arc, Mutex},
};

use diesel::prelude::*;
use diesel::{r2d2::ConnectionManager, MysqlConnection};
use r2d2::Pool;
use serde::Deserialize;
use serde_json::Value;

use crate::schema::vault;
use crate::schema::vault::dsl::*;
use crate::{
    errors::RvError,
    schema::vault::vault_key,
    storage::physical::{Backend, BackendEntry},
};

use super::new;

pub struct MysqlBackend {
    pool: Arc<Mutex<Pool<ConnectionManager<MysqlConnection>>>>,
}

#[derive(Queryable, PartialEq, Debug)]
#[diesel(table_name = vault)]
pub struct MysqlBackendEntry {
    pub vault_key: String,
    pub vault_value: Vec<u8>,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = vault)]
pub struct NewMysqlBackendEntry {
    pub vault_key: String,
    pub vault_value: Vec<u8>,
}

impl Backend for MysqlBackend {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let conn: &mut MysqlConnection = &mut self.pool.lock().unwrap().get().unwrap();

        let results: Result<Vec<MysqlBackendEntry>, _> =
            vault.filter(vault_key.like(format!("{}%", prefix))).load::<MysqlBackendEntry>(conn);

        match results {
            Ok(entries) => {
                let mut keys: Vec<String> = Vec::new();
                for entry in entries {
                    let key = entry.vault_key.clone();
                    let key = key.trim_start_matches(prefix);
                    match key.find('/') {
                        Some(i) => {
                            let key = &key[0..i+1];
                            if !keys.contains(&key.to_string()) {
                                keys.push(key.to_string());
                            }
                        }
                        None => {
                            keys.push(key.to_string());
                        }
                    }
                }
                return Ok(keys);
            }
            Err(e) => return Err(RvError::ErrDatabaseExecuteEntry { source: (e) }),
        }
    }

    fn get(&self, key: &str) -> Result<Option<BackendEntry>, RvError> {
        if key.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let conn: &mut MysqlConnection = &mut self.pool.lock().unwrap().get().unwrap();

        let result: Result<MysqlBackendEntry, _> = vault.filter(vault_key.eq(key)).first::<MysqlBackendEntry>(conn);

        match result {
            Ok(entry) => return Ok(Some(BackendEntry { key: entry.vault_key, value: entry.vault_value })),
            Err(e) => {
                if e == diesel::NotFound {
                    return Ok(None);
                } else {
                    return Err(RvError::ErrDatabaseExecuteEntry { source: (e) });
                }
            }
        }
    }

    fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
        if entry.key.as_str().starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let conn: &mut MysqlConnection = &mut self.pool.lock().unwrap().get().unwrap();

        let new_entry = NewMysqlBackendEntry { vault_key: entry.key.clone(), vault_value: entry.value.clone() };

        match diesel::replace_into(vault).values(&new_entry).execute(conn) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(RvError::ErrDatabaseExecuteEntry { source: (e) }),
        }
    }

    fn delete(&self, key: &str) -> Result<(), RvError> {
        if key.starts_with("/") {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let conn: &mut MysqlConnection = &mut self.pool.lock().unwrap().get().unwrap();

        match diesel::delete(vault.filter(vault_key.eq(key))).execute(conn) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(RvError::ErrDatabaseExecuteEntry { source: (e) }),
        }
    }
}

impl MysqlBackend {
    pub fn new(conf: &HashMap<String, Value>) -> Result<MysqlBackend, RvError> {
        match new(conf) {
            Ok(pool) => Ok(MysqlBackend { pool: Arc::new(Mutex::new(pool)) }),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod test {

    use serde_json::Value;
    use std::collections::HashMap;

    use crate::storage::physical::test::test_backend;
    use crate::storage::physical::test::test_backend_list_prefix;

    use super::MysqlBackend;

    #[test]
    fn test_mysql_backend() {
        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("address".to_string(), Value::String("127.0.0.1:3306".to_string()));
        conf.insert("username".to_string(), Value::String("root".to_string()));
        conf.insert("password".to_string(), Value::String("password".to_string()));

        let backend = MysqlBackend::new(&conf);

        assert!(backend.is_ok());

        let backend = backend.unwrap();

        test_backend(&backend);
        test_backend_list_prefix(&backend);
    }
}
