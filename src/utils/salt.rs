//! This module is a Rust replica of
//! <https://github.com/hashicorp/vault/blob/main/sdk/helper/salt/salt.go>

use openssl::{
    hash::{hash, MessageDigest},
    pkey::PKey,
    nid::Nid,
    sign::Signer,
};
use derivative::Derivative;

use super::{
    generate_uuid,
};

use crate::{
    storage::{Storage, StorageEntry},
    errors::RvError,
};

static DEFAULT_LOCATION: &str = "salt";

#[derive(Debug, Clone)]
pub struct Salt {
    pub config: Config,
    pub salt: String,
    pub generated: bool,
}

#[derive(Derivative)]
#[derivative(Debug, Clone)]
pub struct Config {
    pub location: String,
    #[derivative(Debug="ignore")]
    pub hash_type: MessageDigest,
    #[derivative(Debug="ignore")]
    pub hmac_type: MessageDigest,
}

impl Default for Salt {
    fn default() -> Self {
        Self {
            salt: generate_uuid(),
            generated: true,
            config: Config::default(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            location: DEFAULT_LOCATION.to_string(),
            hash_type: MessageDigest::sha256(),
            hmac_type: MessageDigest::sha256(),
        }
    }
}

impl Salt {
    pub fn new(storage: Option<&dyn Storage>, config: Option<&Config>) -> Result<Self, RvError> {
        let mut salt = Salt::default();
        if let Some(c) = config {
            if salt.config.location != c.location && c.location != "" {
                salt.config.location = c.location.clone();
            }

            if salt.config.hash_type != c.hash_type {
                salt.config.hash_type = c.hash_type.clone();
            }

            if salt.config.hmac_type != c.hmac_type {
                salt.config.hmac_type = c.hmac_type.clone();
            }
        }

        if let Some(s) = storage {
            if let Some(raw) = s.get(&salt.config.location)? {
                salt.salt = String::from_utf8_lossy(&raw.value).to_string();
                salt.generated = false;
            } else {
                let entry = StorageEntry {
                    key: salt.config.location.clone(),
                    value: salt.salt.as_bytes().to_vec(),
                };

                s.put(&entry)?;
            }
        }

        Ok(salt)
    }

    pub fn new_nonpersistent() -> Self {
        let mut salt = Salt::default();
        salt.config.location = "".to_string();
        salt
    }

    pub fn get_hmac(&self, data: &str) -> Result<String, RvError> {
        let pkey = PKey::hmac(self.salt.as_bytes())?;
        let mut signer = Signer::new(self.config.hmac_type, &pkey)?;
        signer.update(data.as_bytes())?;
        let hmac = signer.sign_to_vec()?;
        Ok(hex::encode(hmac.as_slice()))
    }

    pub fn get_identified_hamc(&self, data: &str) -> Result<String, RvError> {
        let hmac_type = match self.config.hmac_type.type_() {
            Nid::SHA256 => "hmac-sha256",
            Nid::SM3 => "hmac-sm3",
            Nid::MD5 => "hmac-md5",
            _ => "hmac-unknown",
        };

        let hmac = self.get_hmac(data)?;

        Ok(format!("{}:{}", hmac_type, hmac))
    }

    pub fn get_hash(&self, data: &str) -> Result<String, RvError> {
        let ret = hash(self.config.hash_type, data.as_bytes())?;
        let bytes = ret.to_vec();
        Ok(hex::encode(bytes.as_slice()))
    }

    pub fn salt_id(&self, id: &str) -> Result<String, RvError> {
        let comb = format!("{}{}", self.salt, id);
        self.get_hash(&comb)
    }

    pub fn did_generate(&self) -> bool {
        self.generated
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, env, fs, sync::Arc};
    use go_defer::defer;
    use rand::{thread_rng, Rng};
    use serde_json::Value;
    use super::*;
    use crate::{
        storage::{
            barrier_view, barrier_aes_gcm,
            barrier::SecurityBarrier,
        }
    };

    #[test]
    fn test_salt() {
        // init the storage
        let dir = env::temp_dir().join("rusty_vault_test_salt");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let mut key = vec![0u8; 32];
        thread_rng().fill(key.as_mut_slice());

        let backend = crate::storage::new_backend("file", &conf);
        assert!(backend.is_ok());
        let backend = backend.unwrap();
        let aes_gcm_view = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

        let init = aes_gcm_view.init(key.as_slice());
        assert!(init.is_ok());

        assert!(aes_gcm_view.unseal(key.as_slice()).is_ok());

        let view = barrier_view::BarrierView::new(Arc::new(aes_gcm_view), "test");

        //test salt
        let salt = Salt::new(Some(view.as_storage()), None);
        assert!(salt.is_ok());

        let salt = salt.unwrap();
        assert!(salt.did_generate());

        let ss = view.get(DEFAULT_LOCATION);
        assert!(ss.is_ok());
        assert!(ss.unwrap().is_some());

        let salt2 = Salt::new(Some(view.as_storage()), Some(&salt.config));
        assert!(salt2.is_ok());

        let salt2 = salt2.unwrap();
        assert!(!salt2.did_generate());

        assert_eq!(salt.salt, salt2.salt);

        let id = "foobarbaz";
        let sid1 = salt.salt_id(id);
        let sid2 = salt2.salt_id(id);
        assert!(sid1.is_ok());
        assert!(sid2.is_ok());

        let sid1 = sid1.unwrap();
        let sid2 = sid2.unwrap();
        assert_eq!(sid1, sid2);
        assert_eq!(sid1.len(), salt.config.hash_type.size()*2);
    }
}
