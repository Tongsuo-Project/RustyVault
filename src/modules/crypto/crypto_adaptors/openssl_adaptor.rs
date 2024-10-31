//! This is the OpenSSL adaptor.

use crate::errors::RvError;
use crate::modules::crypto::{
    AEADCipher, AESKeySize, BlockCipher,
    CipherMode, AES,
    RSA, RSAKeySize,
    PublicKey, PublicKeyType,
    Signature, Encryption
};
use openssl::symm::{Cipher, Crypter, Mode, encrypt, encrypt_aead, decrypt, decrypt_aead};
use openssl::rand::rand_priv_bytes;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use crate::modules::crypto::crypto_adaptors::common;

use zeroize::{Zeroize, Zeroizing};

pub struct AdaptorCTX {
    ctx: Crypter,
    tag_set: bool,
    aad_set: bool,
}

impl AES {
    /// This function is the constructor of the AES struct, it returns a new AES object on success.
    ///
    /// keygen: true stands for generating a key and iv; if false, then the caller needs to feed in
    /// the specific key and iv values through the parameters.
    /// size: bit-length of AES. If omitted, AESKeySize::AES128 is used as default.
    /// mode: cipher mode of AES, such as CBC, GCM, etc. If omitted, CipherMode::CBC is default.
    /// key: symmetric key that is used to encrypt and decrypt data.
    /// iv: initialization vector. This depends on specific mode, for instance, ECB requires no IV.
    pub fn new(
        keygen: bool,
        size: Option<AESKeySize>,
        mode: Option<CipherMode>,
        key: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
    ) -> Result<Self, RvError> {
        common_aes_new!(keygen, size, mode, key, iv);
    }

    /// This function returns the key and iv vaule stored in one AES object.
    ///
    /// Two values are returned in a tuple: the first element represents the key, and the second
    /// element represents the IV. Elements may be None if unset.
    pub fn get_key_iv(&self) -> (Vec<u8>, Vec<u8>) {
        common_get_key_iv!(self);
    }
}

impl BlockCipher for AES {
    fn encrypt(&mut self, plaintext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        common_aes_encrypt!(self, plaintext);
    }

    fn encrypt_update(&mut self, plaintext: Vec<u8>, ciphertext: &mut Vec<u8>
        ) -> Result<usize, RvError> {
        common_aes_encrypt_update!(self, plaintext, ciphertext);
    }

    fn encrypt_final(&mut self, ciphertext: &mut Vec<u8>
        ) -> Result<usize, RvError> {
        common_aes_encrypt_final!(self, ciphertext);
    }

    fn decrypt(&mut self, ciphertext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        common_aes_decrypt!(self, ciphertext);
    }

    fn decrypt_update(&mut self, ciphertext: Vec<u8>, plaintext: &mut Vec<u8>
        ) -> Result<usize, RvError> {
        common_aes_decrypt_update!(self, ciphertext, plaintext);
    }

    fn decrypt_final(&mut self, plaintext: &mut Vec<u8>
        ) -> Result<usize, RvError> {
        common_aes_decrypt_final!(self, plaintext);
    }
}

impl AEADCipher for AES {
    fn set_aad(&mut self, aad: Vec<u8>) -> Result<(), RvError> {
        common_aes_set_aad!(self, aad);
    }
    fn get_tag(&mut self) -> Result<Vec<u8>, RvError> {
        common_aes_get_tag!(self);
    }
    fn set_tag(&mut self, tag: Vec<u8>) -> Result<(), RvError> {
        common_aes_set_tag!(self, tag);
    }
}

pub struct AdaptorPKeyCTX {
    // The private key in OpenSSL context contains also the public key
    private_key: PKey<Private>,
}

// Simply do nothing since OpenSSL will safely clean the memory of a PKEY object (Drop trait)
impl Zeroize for AdaptorPKeyCTX {
    fn zeroize(&mut self) {}
}

impl RSA {
    /// This function is the constructor of the RSA struct, it returns a new RSA object on success.
    ///
    /// size: RSA key size. Valid options are RSA2048 (default), RSA3072, RSA4096, RSA8192.
    /// prime: for multi-prime RSA usage (RFC 8017), default is 2.
    pub fn new(
        prime: Option<u8>,
        size: Option<RSAKeySize>,
    ) -> Result<Self, RvError> {
        return Ok(
            RSA {
                key_type: PublicKeyType::RSA,
                prime: prime.unwrap_or(2),
                size: size.unwrap_or(RSAKeySize::RSA2048),
                ctx: None,
            }
        );
    }
}

impl PublicKey for RSA {
    fn keygen(&mut self) -> Result<(), RvError> {
        let bits: u32;
        match &self.size {
            RSAKeySize::RSA2048 =>  bits = 2048,
            RSAKeySize::RSA3072 =>  bits = 3072,
            RSAKeySize::RSA4096 =>  bits = 4096,
            RSAKeySize::RSA8192 =>  bits = 8192,
        }

        let rsa = match Rsa::generate(bits) {
            Ok(r) => r,
            Err(_e) => return Err(RvError::ErrCryptoPKeyRSAKeyGenFailed),
        };

        let pkey = match PKey::from_rsa(rsa) {
            Ok(r) => r,
            Err(_e) => return Err(RvError::ErrCryptoPKeyRSAKeyGenFailed),
        };

        let adaptor_ctx = AdaptorPKeyCTX { private_key: pkey };
        self.ctx = Some(adaptor_ctx);

        return Ok(());
    }

    fn get_key_type(&self) -> Result<&PublicKeyType, RvError> {
        return Ok(&self.key_type);
    }
}

impl Signature for RSA {
    fn sign(&self, data: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        let key = &self.ctx.as_ref().unwrap().private_key;

        let mut ctx = match PkeyCtx::new(&key) {
            Ok(ctx) => ctx,
            Err(_e) => return Err(RvError::ErrCryptoPKeyInternalError),
        };

        match ctx.sign_init() {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeySignInitFailed),
        }

        let mut signature: Vec<u8> = Vec::new();
        match ctx.sign_to_vec(data, &mut signature) {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeySignFailed),
        }

        return Ok(signature);
    }

    fn verify(&self, data: &Vec<u8>, sig: &Vec<u8>) -> Result<bool, RvError> {
        let key = &self.ctx.as_ref().unwrap().private_key;

        let mut ctx = match PkeyCtx::new(&key) {
            Ok(ctx) => ctx,
            Err(_e) => return Err(RvError::ErrCryptoPKeyInternalError),
        };

        match ctx.verify_init() {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeyVerifyInitFailed),
        }

        let valid = match ctx.verify(data, sig) {
            Ok(ret) => ret,
            Err(_e) => return Err(RvError::ErrCryptoPKeyVerifyFailed),
        };

        return Ok(valid);
    }
}

impl Encryption for RSA {
    fn encrypt(&self, plaintext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        let key = &self.ctx.as_ref().unwrap().private_key;

        let mut ctx = match PkeyCtx::new(&key) {
            Ok(ctx) => ctx,
            Err(_e) => return Err(RvError::ErrCryptoPKeyInternalError),
        };

        match ctx.encrypt_init() {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeyEncInitFailed),
        }

        let mut ciphertext: Vec<u8> = Vec::new();
        match ctx.encrypt_to_vec(plaintext, &mut ciphertext) {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeyEncFailed),
        }

        return Ok(ciphertext);
    }

    fn decrypt(&self, ciphertext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        let key = &self.ctx.as_ref().unwrap().private_key;

        let mut ctx = match PkeyCtx::new(&key) {
            Ok(ctx) => ctx,
            Err(_e) => return Err(RvError::ErrCryptoPKeyInternalError),
        };

        match ctx.decrypt_init() {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeyDecInitFailed),
        }

        let mut plaintext: Vec<u8> = Vec::new();
        match ctx.decrypt_to_vec(ciphertext, &mut plaintext) {
            Ok(_ret) => {},
            Err(_e) => return Err(RvError::ErrCryptoPKeyDecFailed),
        }

        return Ok(plaintext);
    }
}
