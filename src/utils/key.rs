use openssl::{
    pkey::{PKey},
    rsa::{Rsa, Padding},
    ec::{EcGroup, EcKey},
    nid::Nid,
    rand::rand_bytes,
    hash::MessageDigest,
    sign::{Signer, Verifier},
    symm::{Cipher, encrypt, decrypt, encrypt_aead, decrypt_aead},
};
use serde::{Serialize, Deserialize};
use crate::{
    utils::generate_uuid,
    errors::RvError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub key: Vec<u8>,
    //for aes-gcm | aes-cbc
    pub iv: Vec<u8>,
    pub bits: u32,
}

impl Default for KeyBundle {
    fn default() -> Self {
        KeyBundle {
            id: generate_uuid(),
            name: String::new(),
            key_type: String::new(),
            key: Vec::new(),
            iv: Vec::new(),
            bits: 0,
        }
    }
}

impl KeyBundle {
    pub fn new(name: &str, key_type: &str, key_bits: u32) -> Self {
        Self {
            name: name.to_string(),
            key_type: key_type.to_string(),
            bits: key_bits,
            ..KeyBundle::default()
        }
    }

    pub fn generate(&mut self) -> Result<(), RvError> {
        let key_bits = self.bits;
        let priv_key = match self.key_type.as_str() {
            "rsa" => {
                if key_bits != 2048 && key_bits != 3072 && key_bits != 4096 {
                    return Err(RvError::ErrPkiKeyBitsInvalid);
                }
                let rsa_key = Rsa::generate(key_bits)?;
                let pkey = PKey::from_rsa(rsa_key)?;
                pkey.private_key_to_pem_pkcs8()?
            },
            "ec" => {
                let curve_name = match key_bits {
                    224 => Nid::SECP224R1,
                    256 => Nid::SECP256K1,
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };
                let ec_group = EcGroup::from_curve_name(curve_name)?;
                let ec_key = EcKey::generate(ec_group.as_ref())?;
                let pkey = PKey::from_ec_key(ec_key)?;
                pkey.private_key_to_pem_pkcs8()?
            },
            "aes-gcm" | "aes-cbc" | "aes-ecb" => {
                if key_bits != 128 && key_bits != 192 && key_bits != 256 {
                    return Err(RvError::ErrPkiKeyBitsInvalid);
                }

                if self.key_type.as_str() != "aes-ecb" {
                    let mut iv_bytes = vec![0u8; 16];
                    rand_bytes(&mut iv_bytes)?;
                    self.iv = iv_bytes;
                }

                let mut random_bytes = vec![0u8; (key_bits/8) as usize];
                rand_bytes(&mut random_bytes)?;
                random_bytes
            },
            _ => {
                return Err(RvError::ErrPkiKeyTypeInvalid);
            }
        };

        self.key = priv_key;

        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            "rsa" => {
                let rsa = Rsa::private_key_from_pem(&self.key)?;
                let pkey = PKey::from_rsa(rsa)?;
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
                signer.set_rsa_padding(Padding::PKCS1)?;
                signer.update(data)?;
                return Ok(signer.sign_to_vec()?);
            },
            "ec" => {
                let ec_key = EcKey::private_key_from_pem(&self.key)?;
                let pkey = PKey::from_ec_key(ec_key)?;
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
                signer.update(data)?;
                return Ok(signer.sign_to_vec()?);
            },
            _ => {
                return Err(RvError::ErrPkiKeyOperationInvalid);
            }
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, RvError> {
        match self.key_type.as_str() {
            "rsa" => {
                let rsa = Rsa::private_key_from_pem(&self.key)?;
                let pkey = PKey::from_rsa(rsa)?;
                let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
                verifier.set_rsa_padding(Padding::PKCS1)?;
                verifier.update(data)?;
                return Ok(verifier.verify(signature).unwrap_or(false));
            },
            "ec" => {
                let ec_key = EcKey::private_key_from_pem(&self.key)?;
                let pkey = PKey::from_ec_key(ec_key)?;
                let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
                verifier.update(data)?;
                return Ok(verifier.verify(signature).unwrap_or(false));
            },
            _ => {
                return Err(RvError::ErrPkiKeyOperationInvalid);
            }
        }
    }

    pub fn encrypt(&self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            "aes-gcm" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_gcm(),
                    192 => Cipher::aes_192_gcm(),
                    256 => Cipher::aes_256_gcm(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };
                let mut tag = vec![0u8; 16];
                let mut ciphertext = encrypt_aead(cipher, &self.key, Some(&self.iv), aad.unwrap_or("".as_bytes()), data, &mut tag)?;
                ciphertext.extend_from_slice(&tag);
                Ok(ciphertext)

            },
            "aes-cbc" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_cbc(),
                    192 => Cipher::aes_192_cbc(),
                    256 => Cipher::aes_256_cbc(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };

                Ok(encrypt(cipher, &self.key, Some(&self.iv), data)?)
            },
            "aes-ecb" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_ecb(),
                    192 => Cipher::aes_192_ecb(),
                    256 => Cipher::aes_256_ecb(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };

                Ok(encrypt(cipher, &self.key, None, data)?)
            },
            _ => {
                return Err(RvError::ErrPkiKeyOperationInvalid);
            }
        }
    }

    pub fn decrypt(&self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            "aes-gcm" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_gcm(),
                    192 => Cipher::aes_192_gcm(),
                    256 => Cipher::aes_256_gcm(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };
                let (ciphertext, tag) = data.split_at(data.len() - 16);
                Ok(decrypt_aead(cipher, &self.key, Some(&self.iv), aad.unwrap_or("".as_bytes()), ciphertext, tag)?)

            },
            "aes-cbc" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_cbc(),
                    192 => Cipher::aes_192_cbc(),
                    256 => Cipher::aes_256_cbc(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };

                Ok(decrypt(cipher, &self.key, Some(&self.iv), data)?)
            },
            "aes-ecb" => {
                let cipher = match self.bits {
                    128 => Cipher::aes_128_ecb(),
                    192 => Cipher::aes_192_ecb(),
                    256 => Cipher::aes_256_ecb(),
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };

                Ok(decrypt(cipher, &self.key, None, data)?)
            },
            _ => {
                return Err(RvError::ErrPkiKeyOperationInvalid);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_key_sign_verify(key_bundle: &mut KeyBundle) {
        assert!(key_bundle.generate().is_ok());
        let data = "123456789";
        let signature = key_bundle.sign(data.as_bytes());
        assert!(signature.is_ok());
        assert!(signature.as_ref().unwrap().len() > data.len());
        let verify = key_bundle.verify(data.as_bytes(), signature.as_ref().unwrap());
        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }

    fn test_key_encrypt_decrypt(key_bundle: &mut KeyBundle, aad: Option<&[u8]>) {
        assert!(key_bundle.generate().is_ok());
        let data = "123456789";
        let result = key_bundle.encrypt(data.as_bytes(), aad);
        assert!(result.is_ok());
        let encrypted_data = result.unwrap();
        let result = key_bundle.decrypt(&encrypted_data, aad);
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert_eq!(std::str::from_utf8(&decrypted_data).unwrap(), data);
    }

    #[test]
    fn test_rsa_key_operation() {
        let mut key_bundle = KeyBundle::new("rsa-2048", "rsa", 2048);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("rsa-3072", "rsa", 3072);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("rsa-4096", "rsa", 4096);
        test_key_sign_verify(&mut key_bundle);
    }

    #[test]
    fn test_ec_key_operation() {
        let mut key_bundle = KeyBundle::new("ec-224", "ec", 224);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-256", "ec", 256);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-384", "ec", 384);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-521", "ec", 521);
        test_key_sign_verify(&mut key_bundle);
    }

    #[test]
    fn test_aes_key_operation() {
        // test aes-gcm
        let mut key_bundle = KeyBundle::new("aes-gcm-128", "aes-gcm", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some("rusty_vault".as_bytes()));
        let mut key_bundle = KeyBundle::new("aes-gcm-192", "aes-gcm", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some("rusty_vault".as_bytes()));
        let mut key_bundle = KeyBundle::new("aes-gcm-256", "aes-gcm", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some("rusty_vault".as_bytes()));
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some("rusty_vault".as_bytes()));

        // test aes-cbc
        let mut key_bundle = KeyBundle::new("aes-cbc-128", "aes-cbc", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-cbc-192", "aes-cbc", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-cbc-256", "aes-cbc", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);

        // test aes-ecb
        let mut key_bundle = KeyBundle::new("aes-ecb-128", "aes-ecb", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-ecb-192", "aes-ecb", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-ecb-256", "aes-ecb", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);
    }
}
