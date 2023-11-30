use std::sync::{RwLock, Arc};
use rand::{Rng, thread_rng};
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::{CipherCtx};
use serde::{Serialize, Deserialize};
use crate::errors::RvError;
use super::{Storage, StorageEntry};
use super::barrier::{SecurityBarrier, BARRIER_INIT_PATH};
use super::physical::{Backend, BackendEntry};

const EPOCH_SIZE: usize = 4;
const KEY_EPOCH: u8 = 1;
const AES_GCM_VERSION: u8 = 0x1;
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BarrierInit {
    version: u32,
    key: Vec<u8>,
}

struct BarrierInfo {
    sealed: bool,
    key: Option<Vec<u8>>,
    cipher: Option<&'static CipherRef>,
    cipher_ctx: Option<RwLock<CipherCtx>>,
}

pub struct AESGCMBarrier {
    barrier_info: Arc<RwLock<BarrierInfo>>,
    backend: Arc<dyn Backend>,
}

impl Storage for AESGCMBarrier {
    fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.sealed {
            return Err(RvError::ErrBarrierSealed);
        }
        self.backend.list(prefix)
    }

    fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        // Read the key from the backend
        let pe = self.backend.get(key)?;
        if pe.is_none() {
            return Ok(None);
        }

        // Decrypt the ciphertext
        let plain = self.decrypt(pe.as_ref().unwrap().value.as_slice())?;
        let entry = StorageEntry{
            key: key.to_string(),
            value: plain,
        };

        Ok(Some(entry))
    }

    fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let ciphertext = self.encrypt(entry.value.as_slice())?;

        let be = BackendEntry {
            key: entry.key.clone(),
            value: ciphertext,
        };

        self.backend.put(&be)?;

        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.sealed {
            return Err(RvError::ErrBarrierSealed);
        }
        self.backend.delete(key)
    }
}

impl SecurityBarrier for AESGCMBarrier {
    fn inited(&self) -> Result<bool, RvError> {
        let res = self.backend.get(BARRIER_INIT_PATH)?;
        Ok(res.is_some())
    }

    fn init(&self, key: &[u8]) -> Result<(), RvError> {
        let (min, max) = self.key_length_range();
        if key.len() < min || key.len() > max {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        // Check if already initialized
        let inited = self.inited()?;
        if inited {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        let encrypt_key = self.generate_key()?;

        let barrier_init = BarrierInit {
            version: 1,
            key: encrypt_key,
        };

        let serialized_barrier_init = serde_json::to_string(&barrier_init)?;

        self.init_cipher(key)?;

        let value = self.encrypt(serialized_barrier_init.as_bytes())?;

        let be = BackendEntry {
            key: BARRIER_INIT_PATH.to_string(),
            value: value,
        };

        self.backend.put(&be)?;

        self.reset_cipher()?;

        Ok(())
    }

    fn generate_key(&self) -> Result<Vec<u8>, RvError> {
        let key_size = 2 * AES_BLOCK_SIZE;
        let mut buf = vec![0u8; key_size];

        thread_rng().fill(buf.as_mut_slice());
        Ok(buf)
    }

    fn key_length_range(&self) -> (usize, usize) {
        (AES_BLOCK_SIZE, 2 * AES_BLOCK_SIZE)
    }

    fn sealed(&self) -> Result<bool, RvError> {
        let barrier_info = self.barrier_info.read()?;
        Ok(barrier_info.sealed)
    }

    fn unseal(&self, key: &[u8]) -> Result<(), RvError> {
        let sealed = self.sealed()?;
        if !sealed {
            return Ok(());
        }

        let entry = self.backend.get(BARRIER_INIT_PATH)?;
        if entry.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        self.init_cipher(key)?;

        let value = self.decrypt(entry.unwrap().value.as_slice());
        if value.is_err() {
            return Err(RvError::ErrBarrierUnsealFailed);
        }
        let barrier_init: BarrierInit = serde_json::from_slice(value.unwrap().as_slice())?;

        self.init_cipher(barrier_init.key.as_slice())?;

        let mut barrier_info = self.barrier_info.write()?;
        barrier_info.sealed = false;

        Ok(())
    }

    fn seal(&self) -> Result<(), RvError> {
        self.reset_cipher()?;
        let mut barrier_info = self.barrier_info.write()?;
        barrier_info.sealed = true;
        Ok(())
    }

    fn as_storage(&self) -> &dyn Storage {
        self
    }
}

impl AESGCMBarrier {
    pub fn new(physical: Arc<dyn Backend>) -> Self {
        Self {
            backend: physical,
            barrier_info: Arc::new(RwLock::new(BarrierInfo {
                sealed: true,
                key: None,
                cipher: None,
                cipher_ctx: None,
            })),
        }
    }

    fn init_cipher(&self, key: &[u8]) -> Result<(), RvError> {
        let cipher_ctx = CipherCtx::new()?;
        let mut barrier_info = self.barrier_info.write()?;
        barrier_info.key = Some(key.to_vec());
        barrier_info.cipher = Some(Cipher::aes_256_gcm());
        barrier_info.cipher_ctx = Some(RwLock::new(cipher_ctx));
        Ok(())
    }

    fn reset_cipher(&self) -> Result<(), RvError> {
        let mut barrier_info = self.barrier_info.write()?;
        barrier_info.key = None;
        barrier_info.cipher = None;
        barrier_info.cipher_ctx = None;
        Ok(())
    }
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.key.is_none() || barrier_info.cipher_ctx.is_none() || barrier_info.cipher.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        let cipher = barrier_info.cipher.unwrap();
        let mut cipher_ctx = barrier_info.cipher_ctx.as_ref().unwrap().write()?;
        let key = barrier_info.key.clone().unwrap();

        // Assuming nonce size is the same as IV size
        let nonce_size = cipher.iv_length();

        // Generate a random nonce
        let mut nonce = vec![0u8; nonce_size];
        thread_rng().fill(nonce.as_mut_slice());

        // Encrypt
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher_ctx.encrypt_init(Some(cipher), Some(key.as_slice()), Some(nonce.as_slice()))?;
        cipher_ctx.set_padding(false);
        let len = cipher_ctx.cipher_update(plaintext, Some(&mut ciphertext))?;
        let _final_len = cipher_ctx.cipher_final(&mut ciphertext[len..])?;

        let tag_size = cipher_ctx.tag_length();
        let mut tag = vec![0u8; tag_size];
        cipher_ctx.tag(tag.as_mut_slice())?;

        let size: usize = EPOCH_SIZE + 1 + nonce_size + ciphertext.len() + tag_size;
        let mut out = vec![0u8; size];

        out[3] = KEY_EPOCH;
        out[4] = AES_GCM_VERSION;
        out[5..5+nonce_size].copy_from_slice(nonce.as_slice());
        out[5+nonce_size..5+nonce_size+ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        out[5+nonce_size+ciphertext.len()..size].copy_from_slice(tag.as_slice());

        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RvError> {
        let barrier_info = self.barrier_info.read()?;
        if barrier_info.key.is_none() || barrier_info.cipher_ctx.is_none() || barrier_info.cipher.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        if ciphertext[0] != 0 || ciphertext[1] != 0 || ciphertext[2] != 0 || ciphertext[3] != KEY_EPOCH {
            return Err(RvError::ErrBarrierEpochMismatch);
        }

        let cipher = barrier_info.cipher.unwrap();
        let mut cipher_ctx = barrier_info.cipher_ctx.as_ref().unwrap().write()?;
        let key = barrier_info.key.clone().unwrap();

        let nonce_size = cipher.iv_length();

        if ciphertext[4] != AES_GCM_VERSION {
            return Err(RvError::ErrBarrierVersionMismatch);
        }

        let nonce = &ciphertext[5..5+nonce_size];

        cipher_ctx.decrypt_init(Some(cipher), Some(key.as_slice()), Some(nonce))?;
        cipher_ctx.set_padding(false);

        let tag_size = cipher_ctx.tag_length();
        let raw = &ciphertext[5+nonce_size..ciphertext.len()-tag_size];
        let tag = &ciphertext[ciphertext.len()-tag_size..ciphertext.len()];
        let size = ciphertext.len() - 5 - nonce_size - tag_size;
        let mut out = vec![0u8; size];

        cipher_ctx.set_tag(tag)?;
        let len = cipher_ctx.cipher_update(raw, Some(&mut out))?;
        let final_len = cipher_ctx.cipher_final(&mut out[len..])?;
        out.truncate(len + final_len);

        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs;
    use std::collections::HashMap;
    use serde_json::Value;
    use go_defer::defer;
    use super::*;
    use super::super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let dir = env::temp_dir().join("rusty_vault_test_encrypt_decrypt");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let cipher = Cipher::aes_256_gcm();
        let ctx = CipherCtx::new();
        assert!(ctx.is_ok());
        let cipher_ctx = ctx.unwrap();

        let mut key = vec![0u8; cipher.key_length()];
        thread_rng().fill(key.as_mut_slice());

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = AESGCMBarrier {
            backend: backend,
            barrier_info: Arc::new(RwLock::new(BarrierInfo {
                sealed: true,
                key: Some(key),
                cipher: Some(cipher),
                cipher_ctx: Some(RwLock::new(cipher_ctx)),
            })),
        };

        let plaintext = "rusty vault test";
        let res = barrier.encrypt(plaintext.as_bytes());
        assert!(res.is_ok());
        let res = barrier.decrypt(res.unwrap().as_slice());
        assert!(res.is_ok());
    }

    #[test]
    fn test_decrypt() {
        let dir = env::temp_dir().join("rusty_vault_test_decrypt");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let cipher = Cipher::aes_256_gcm();
        let ctx = CipherCtx::new();
        assert!(ctx.is_ok());
        let cipher_ctx = ctx.unwrap();

        let key = vec![121, 133, 170, 204, 71, 77, 160, 134, 22, 37, 254, 206, 120,
                        206, 143, 197, 150, 83, 5, 45, 121, 51, 124, 110, 162, 1,
                        9, 51, 16, 75, 157, 129];

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = AESGCMBarrier {
            backend: backend,
            barrier_info: Arc::new(RwLock::new(BarrierInfo {
                sealed: true,
                key: Some(key),
                cipher: Some(cipher),
                cipher_ctx: Some(RwLock::new(cipher_ctx)),
            })),
        };

        let ciphertext = &[0, 0, 0, 1, 1, 99, 115, 28, 164, 208, 39, 20, 70, 150,
                            217, 80, 159, 80, 251, 42, 49, 32, 136, 109, 90, 160,
                            217, 227, 252, 159, 54, 194, 68, 146, 37, 88, 57, 225,
                            144, 96, 105, 160, 187, 112, 145, 175, 24, 89, 33];
        let res = barrier.decrypt(ciphertext);
        assert!(res.is_ok());
    }

    #[test]
    fn test_barriew_aes256_gcm() {
        let dir = env::temp_dir().join("rusty_vault_test_barriew_aes256_gcm");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = AESGCMBarrier::new(Arc::clone(&backend));

        let inited = barrier.inited();
        assert!(inited.is_ok());
        assert!(!inited.unwrap());

        let sealed = barrier.sealed();
        assert!(sealed.is_ok());
        assert!(sealed.unwrap());

        let mut key = vec![0u8; 32];
        thread_rng().fill(key.as_mut_slice());
        let init = barrier.init(key.as_slice());
        assert!(init.is_ok());

        let sealed = barrier.sealed();
        assert!(sealed.is_ok());
        assert!(sealed.unwrap());

        let unseal = barrier.unseal(key.as_slice());
        assert!(unseal.is_ok());

        let sealed = barrier.sealed();
        assert!(sealed.is_ok());
        assert!(!sealed.unwrap());

        let seal = barrier.seal();
        assert!(seal.is_ok());

        let sealed = barrier.sealed();
        assert!(sealed.is_ok());
        assert!(sealed.unwrap());
    }

    #[test]
    fn test_barriew_storage_api() {
        let dir = env::temp_dir().join("rusty_vault_test_barriew_storage_api");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = AESGCMBarrier::new(Arc::clone(&backend));

        let mut key = vec![0u8; 32];
        thread_rng().fill(key.as_mut_slice());
        let init = barrier.init(key.as_slice());
        assert!(init.is_ok());

        let unseal = barrier.unseal(key.as_slice());
        assert!(unseal.is_ok());

        let list = barrier.list("/bin");
        assert!(list.is_err());

        let list = barrier.list("");
        assert!(list.is_ok());
        assert_eq!(list.unwrap().len(), 1);

        let list = barrier.list("xxx");
        assert!(list.is_ok());
        assert_eq!(list.unwrap().len(), 0);

        let get = barrier.get("");
        assert!(get.is_ok());
        assert!(get.unwrap().is_none());

        let get = barrier.get("bar");
        assert!(get.is_ok());
        assert!(get.unwrap().is_none());

        let get = barrier.get("/");
        assert!(get.is_err());

        let entry1 = StorageEntry {
            key: "bar".to_string(),
            value: "test1".as_bytes().to_vec(),
        };
        let entry2 = StorageEntry {
            key: "bar/foo".to_string(),
            value: "test2".as_bytes().to_vec(),
        };
        let entry3 = StorageEntry {
            key: "bar/foo/goo".to_string(),
            value: "test3".as_bytes().to_vec(),
        };

        let put = barrier.put(&entry1);
        assert!(put.is_ok());

        let put = barrier.put(&entry2);
        assert!(put.is_ok());

        let put = barrier.put(&entry3);
        assert!(put.is_ok());

        // test the root
        let keys = barrier.list("");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.join("") == "barbarrier/bar/"
                || keys.join("") == "barbar/barrier/"
                || keys.join("") == "bar/barbarrier/"
                || keys.join("") == "barrier/bar/bar"
                || keys.join("") == "barrier/barbar/"
                || keys.join("") == "bar/barrier/bar");
        let get = barrier.get("bar");
        assert!(get.is_ok());
        assert_eq!(get.unwrap().unwrap().value, "test1".as_bytes());

        // test bar/
        let keys = barrier.list("bar/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "foofoo/" || keys.join("") == "foo/foo");
        let get = barrier.get("bar/foo");
        assert!(get.is_ok());
        assert_eq!(get.unwrap().unwrap().value, "test2".as_bytes());

        // test bar/foo/
        let keys = barrier.list("bar/foo/");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "goo".to_string());
        let get = barrier.get("bar/foo/goo");
        assert!(get.is_ok());
        assert_eq!(get.unwrap().unwrap().value, "test3".as_bytes());

        // backend entry value should be encrypted
        let get = barrier.backend.get("bar/foo/goo");
        assert!(get.is_ok());
        assert_ne!(get.unwrap().unwrap().value, "test3".as_bytes());

        // after deletion, should not be able to get the entry
        let delete = barrier.delete("bar");
        assert!(delete.is_ok());
        let get = barrier.get("bar");
        assert!(get.is_ok());
        assert!(get.unwrap().is_none());
        let keys = barrier.list("");
        assert!(keys.is_ok());
        let keys = keys.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.join("") == "barrier/bar/" || keys.join("") == "bar/barrier/");

        let seal = barrier.seal();
        assert!(seal.is_ok());

        // after sealing, all API operations should result in errors
        let keys = barrier.list("");
        assert!(keys.is_err());
        let put = barrier.put(&entry1);
        assert!(put.is_err());
        let get = barrier.get("bar/foo");
        assert!(get.is_err());
        let delete = barrier.delete("bar/foo");
        assert!(delete.is_err());
    }
}
