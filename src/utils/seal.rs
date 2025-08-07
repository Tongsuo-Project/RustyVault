//! This crate is the 'library' part of RustyVault, a Rust and real free replica of Hashicorp Vault.
//! RustyVault is focused on identity-based secrets management and works in two ways independently:
//!
//! 1. A standalone application serving secrets management via RESTful API;
//! 2. A Rust crate that provides same features for other application to integrate.
//!
//! This document is only about the crate part of RustyVault. For the first working mode,
//! please go to RustyVault's [RESTful API documentation], which documents all RustyVault's RESTful API.
//! Users can use an HTTP client tool (curl, e.g.) to send commands to a running RustyVault server and
//! then have relevant secret management features.
//!
//! The second working mode, which works as a typical Rust crate called `rusty_vault`, allows Rust
//! application developers to integrate RustyVault easily into their own applications to have the
//! ability of secrets management such as secure key/vaule storage, public key cryptography, data
//! encryption and so forth.
//!
//! This is the official documentation of crate `rusty_vault`, and it's mainly for developers.
//! Once again, if you are looking for how to use the RustyVault server via a set of RESTful API,
//! then you may prefer the RustyVault's [RESTful API documentation].
//!
//! [Hashicorp Vault]: https://www.hashicorp.com/products/vault
//! [RESTful API documentation]: https://www.tongsuo.net

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    modules::crypto::{AEADCipher, AESKeySize, BlockCipher, CipherMode, AES},
    shamir::ShamirSecret,
};

/// Error types that can occur during SealBox operations.
///
/// This enum provides a unified error type for all SealBox operations,
/// including creation, sealing, unsealing, and data access operations.
#[derive(Debug, Error)]
pub enum SealBoxError {
    /// The SealBox is currently sealed and data access is not allowed.
    ///
    /// This error occurs when trying to access data from a sealed SealBox.
    /// The SealBox must be unsealed with sufficient shares before data can be accessed.
    #[error("SealBox is sealed")]
    Sealed,

    /// The SealBox is not sealed when it should be.
    ///
    /// This error occurs when trying to perform operations that require
    /// the SealBox to be in a sealed state, but it's currently unsealed.
    #[error("SealBox is not sealed")]
    NotSealed,

    /// The SealBox is in the process of being unsealed but doesn't have enough shares yet.
    ///
    /// This error occurs when providing shares for unsealing, but the threshold
    /// number of shares hasn't been reached yet. Continue providing shares until
    /// the threshold is met.
    #[error("SealBox is unsealing")]
    Unsealing,

    /// The decryption operation failed.
    ///
    /// This error occurs when the AES-GCM decryption process fails, typically
    /// due to corrupted ciphertext, invalid authentication tag, or incorrect key.
    #[error("Decryption failed")]
    DecryptionFailed,

    /// The unsealing operation failed due to insufficient or invalid shares.
    ///
    /// This error occurs when the Shamir secret sharing reconstruction fails,
    /// typically due to insufficient shares, invalid shares, or corrupted share data.
    #[error("Unsealing failed: insufficient or invalid shares")]
    UnsealFailed,

    /// The encryption operation failed.
    ///
    /// This error occurs when the AES-GCM encryption process fails, typically
    /// due to issues with key generation, nonce generation, or encryption parameters.
    #[error("Encryption failed")]
    EncryptionFailed,

    /// The Shamir secret splitting operation failed.
    ///
    /// This error occurs when creating shares from the master key fails,
    /// typically due to invalid threshold or total shares parameters.
    #[error("Shamir secret split failed")]
    ShamirSecretSplitFailed,

    /// The Shamir secret combining operation failed.
    ///
    /// This error occurs when reconstructing the master key from shares fails,
    /// typically due to insufficient shares or corrupted share data.
    #[error("Shamir secret combine failed")]
    ShamirSecretCombineFailed,
}

/// A secure container that encrypts data and distributes the decryption key using Shamir's Secret Sharing.
///
/// SealBox provides a secure way to store sensitive data by encrypting it with AES-256-GCM
/// and then splitting the encryption key using Shamir's Secret Sharing scheme. This allows
/// the data to be securely distributed among multiple parties, requiring a threshold number
/// of shares to reconstruct the key and access the data.
///
/// # Type Parameters
/// - `T`: The type of data to be stored. Must implement `Serialize` and `Deserialize`.
///
/// # Security Features
/// - Uses AES-256-GCM for authenticated encryption
/// - Implements Shamir's Secret Sharing for key distribution
/// - Automatic zeroization of sensitive data on drop
/// - Supports serialization/deserialization for persistence
/// - Configurable threshold and total shares for flexible access control
///
/// # Usage
/// 1. Create a SealBox with data, threshold, and total shares
/// 2. Distribute the shares to different parties
/// 3. To access data, collect threshold number of shares
/// 4. Use the shares to unseal the box and access the data
/// 5. Re-seal the box when done to secure the data again
#[derive(Default, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SealBox<T> {
    /// The encrypted data (ciphertext)
    sealed_data: Vec<u8>,
    /// The nonce used for AES-GCM encryption (16 bytes)
    nonce: [u8; 16],
    /// Additional Authenticated Data (AAD) for GCM mode (13 bytes)
    aad: [u8; 13],
    /// The authentication tag from AES-GCM (16 bytes)
    tag: [u8; 16],
    /// The minimum number of shares required to unseal the box
    threshold: u8,
    /// The Shamir shares for reconstructing the encryption key
    ///
    /// This field is skipped during serialization for security reasons.
    /// Shares are only stored in memory and not persisted.
    #[serde(skip)]
    shares: Option<Vec<Vec<u8>>>,
    /// The reconstructed encryption key (32 bytes for AES-256)
    ///
    /// This field is skipped during serialization for security reasons.
    /// The key is only stored in memory when the box is unsealed.
    #[serde(skip)]
    key: Option<[u8; 32]>,
    /// The decrypted and deserialized data
    ///
    /// This field is skipped during serialization and zeroization.
    /// The value is only stored in memory when the box is unsealed.
    #[serde(skip)]
    #[zeroize(skip)]
    value: Option<T>,
}

impl<T> SealBox<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Creates a new SealBox with the given data, threshold, and total shares.
    ///
    /// This method encrypts the provided data using AES-256-GCM and then splits
    /// the encryption key using Shamir's Secret Sharing scheme. The data is immediately
    /// available after creation, but the box can be sealed to secure the data.
    ///
    /// # Arguments
    /// - `data`: The data to be encrypted and stored
    /// - `threshold`: The minimum number of shares required to unseal the box (must be >= 2)
    /// - `total_shares`: The total number of shares to generate (must be >= threshold)
    ///
    /// # Returns
    /// A `Result` containing the new SealBox, or an error if creation fails.
    ///
    /// # Errors
    /// - Returns `SealBoxError::ShamirSecretSplitFailed` if threshold < 2 or total_shares < threshold
    /// - Returns `SealBoxError::EncryptionFailed` if the encryption process fails
    ///
    /// # Security
    /// - Uses AES-256-GCM for authenticated encryption
    /// - Generates cryptographically secure random key and nonce
    /// - Uses current timestamp as additional authenticated data
    /// - Implements Shamir's Secret Sharing for key distribution
    pub fn new(data: T, threshold: u8, total_shares: u8) -> Result<Self, SealBoxError> {
        if threshold < 2 || total_shares < threshold {
            return Err(SealBoxError::ShamirSecretSplitFailed);
        }

        let serialized = serde_json::to_vec(&data).unwrap();

        let now_ms = Utc::now().timestamp_millis().to_string().as_bytes().to_vec();

        let mut aes_encrypter = AES::new(true, Some(AESKeySize::AES256), Some(CipherMode::GCM), None, None)
            .map_err(|_| SealBoxError::EncryptionFailed)?;

        aes_encrypter.set_aad(now_ms.clone()).map_err(|_| SealBoxError::EncryptionFailed)?;
        let encrypted = aes_encrypter.encrypt(&serialized).map_err(|_| SealBoxError::EncryptionFailed)?;

        let mut tag: [u8; 16] = [0; 16];
        tag[..16].copy_from_slice(&aes_encrypter.get_tag().map_err(|_| SealBoxError::EncryptionFailed)?);

        let mut key: [u8; 32] = [0; 32];
        key[..32].copy_from_slice(&aes_encrypter.get_key_iv().0);

        let mut nonce: [u8; 16] = [0; 16];
        nonce[..16].copy_from_slice(&aes_encrypter.get_key_iv().1);

        let mut aad: [u8; 13] = [0; 13];
        aad[..13].copy_from_slice(&now_ms);

        let shares =
            ShamirSecret::split(&key, total_shares, threshold).map_err(|_| SealBoxError::ShamirSecretSplitFailed)?;

        Ok(Self {
            sealed_data: encrypted,
            nonce,
            aad,
            tag,
            threshold,
            shares: Some(shares.deref().clone()),
            key: Some(key),
            value: Some(data),
        })
    }

    /// Retrieves the Shamir shares for this SealBox.
    ///
    /// This method returns a reference to the shares that can be distributed
    /// to different parties. The shares are only available if the box was
    /// created with shares (i.e., not after being sealed).
    ///
    /// # Returns
    /// An `Option` containing a reference to the shares, or `None` if shares
    /// are not available (e.g., after sealing).
    ///
    /// # Security
    /// - Shares are only stored in memory and not persisted
    /// - Shares are cleared when the box is sealed
    pub fn get_shares(&self) -> Option<&Vec<Vec<u8>>> {
        self.shares.as_ref()
    }

    /// Attempts to unseal the box using the provided share.
    ///
    /// This method adds the provided share to the collection and attempts to
    /// reconstruct the encryption key using Shamir's Secret Sharing. If enough
    /// shares are provided (equal to or greater than the threshold), the box
    /// is unsealed and the data becomes accessible.
    ///
    /// # Arguments
    /// - `unseal_key`: A share to add to the collection for unsealing
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the unsealing operation.
    ///
    /// # Errors
    /// - Returns `SealBoxError::NotSealed` if the box is already unsealed
    /// - Returns `SealBoxError::Unsealing` if not enough shares have been provided yet
    /// - Returns `SealBoxError::UnsealFailed` if the shares are invalid or corrupted
    /// - Returns `SealBoxError::DecryptionFailed` if decryption fails
    ///
    /// # Security
    /// - Uses Shamir's Secret Sharing to reconstruct the encryption key
    /// - Validates authentication tag to ensure data integrity
    /// - Clears shares after successful unsealing for security
    pub fn unseal(&mut self, unseal_key: &[u8]) -> Result<(), SealBoxError> {
        if self.is_unsealed() {
            return Err(SealBoxError::NotSealed);
        }

        let Some(shares) = self.shares.as_mut() else {
            self.shares = Some(vec![unseal_key.to_vec()]);
            return Err(SealBoxError::Unsealing);
        };

        if shares.len() < self.threshold as usize {
            shares.push(unseal_key.to_vec());
        }

        if shares.len() < self.threshold as usize {
            return Err(SealBoxError::Unsealing);
        }

        let key = ShamirSecret::combine(shares.clone()).ok_or(SealBoxError::UnsealFailed)?;

        let mut aes_decrypter = AES::new(
            false,
            Some(AESKeySize::AES256),
            Some(CipherMode::GCM),
            Some(key.to_vec()),
            Some(self.nonce.to_vec()),
        )
        .map_err(|_| SealBoxError::DecryptionFailed)?;

        aes_decrypter.set_aad(self.aad.to_vec()).map_err(|_| SealBoxError::DecryptionFailed)?;
        aes_decrypter.set_tag(self.tag.to_vec()).map_err(|_| SealBoxError::DecryptionFailed)?;

        let decrypted = aes_decrypter.decrypt(&self.sealed_data).map_err(|_| SealBoxError::DecryptionFailed)?;

        let value: T = serde_json::from_slice(&decrypted).map_err(|_| SealBoxError::DecryptionFailed)?;

        let key: [u8; 32] = key.try_into().map_err(|_| SealBoxError::UnsealFailed)?;

        self.key = Some(key);
        self.value = Some(value);
        Ok(())
    }

    /// Seals the box, clearing all sensitive data from memory.
    ///
    /// This method clears the shares, key, and decrypted value from memory,
    /// effectively sealing the box and requiring re-unsealing to access data.
    ///
    /// # Security
    /// - Clears all sensitive data from memory
    /// - Forces re-unsealing to access data again
    /// - Helps prevent memory-based attacks
    pub fn seal(&mut self) {
        self.shares = None;
        self.key = None;
        self.value = None;
    }

    /// Checks if the box is currently unsealed.
    ///
    /// This method returns `true` if the box has been successfully unsealed
    /// and the data is accessible, `false` otherwise.
    ///
    /// # Returns
    /// `true` if the box is unsealed and data is accessible, `false` otherwise.
    pub fn is_unsealed(&self) -> bool {
        self.key.is_some()
    }

    /// Retrieves an immutable reference to the stored data.
    ///
    /// This method returns a reference to the decrypted data if the box
    /// is unsealed, or an error if the box is sealed.
    ///
    /// # Returns
    /// A `Result` containing a reference to the data, or an error if the box is sealed.
    ///
    /// # Errors
    /// - Returns `SealBoxError::Sealed` if the box is not unsealed
    pub fn get(&self) -> Result<&T, SealBoxError> {
        self.value.as_ref().ok_or(SealBoxError::Sealed)
    }

    /// Retrieves a mutable reference to the stored data.
    ///
    /// This method returns a mutable reference to the decrypted data if the box
    /// is unsealed, allowing modification of the stored data.
    ///
    /// # Returns
    /// A `Result` containing a mutable reference to the data, or an error if the box is sealed.
    ///
    /// # Errors
    /// - Returns `SealBoxError::Sealed` if the box is not unsealed
    ///
    /// # Security
    /// - Modifications to the data are not automatically re-encrypted
    /// - Call `seal()` and `unseal()` again to persist changes
    pub fn get_mut(&mut self) -> Result<&mut T, SealBoxError> {
        self.value.as_mut().ok_or(SealBoxError::Sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
    struct TestData {
        message: String,
        number: i32,
        flag: bool,
    }

    #[test]
    fn test_sealbox_new() {
        let test_data = TestData { message: "Hello, SealBox!".to_string(), number: 42, flag: true };

        let sealbox = SealBox::new(test_data.clone(), 2, 3);
        assert!(sealbox.is_ok());

        let sealbox = sealbox.unwrap();
        assert!(sealbox.is_unsealed());
        assert!(sealbox.get().is_ok());
        assert!(sealbox.get_shares().is_some());
        assert_eq!(sealbox.get_shares().unwrap().len(), 3);
    }

    #[test]
    fn test_sealbox_unseal_success() {
        let test_data = TestData { message: "Test message".to_string(), number: 123, flag: false };

        let mut sealbox = SealBox::new(test_data.clone(), 2, 3).unwrap();
        let shares = sealbox.get_shares().unwrap().clone();

        assert!(sealbox.get().is_ok());

        sealbox.seal();

        assert!(!sealbox.is_unsealed());

        assert!(sealbox.get().is_err());
        assert!(sealbox.get_shares().is_none());
        assert!(sealbox.key.is_none());
        assert!(sealbox.value.is_none());

        assert!(matches!(sealbox.unseal(&shares[0]).unwrap_err(), SealBoxError::Unsealing));
        assert!(sealbox.unseal(&shares[1]).is_ok());

        assert!(sealbox.is_unsealed());
        let retrieved_data = sealbox.get().unwrap();
        assert_eq!(*retrieved_data, test_data);
    }

    #[test]
    fn test_sealbox_unseal_insufficient_shares() {
        let test_data = TestData { message: "Test message".to_string(), number: 123, flag: false };

        let mut sealbox = SealBox::new(test_data, 3, 5).unwrap();
        let shares = sealbox.get_shares().unwrap().clone();

        sealbox.seal();

        assert!(matches!(sealbox.unseal(&shares[0]).unwrap_err(), SealBoxError::Unsealing));
        assert!(matches!(sealbox.unseal(&shares[1]).unwrap_err(), SealBoxError::Unsealing));

        assert!(!sealbox.is_unsealed());
    }

    #[test]
    fn test_sealbox_unseal_invalid_shares() {
        let test_data = TestData { message: "Test message".to_string(), number: 123, flag: false };

        let mut sealbox = SealBox::new(test_data, 2, 3).unwrap();
        let shares = sealbox.get_shares().unwrap().clone();

        sealbox.seal();

        let invalid_share = vec![0u8; 32];
        assert!(matches!(sealbox.unseal(&invalid_share).unwrap_err(), SealBoxError::Unsealing));
        assert!(matches!(sealbox.unseal(&shares[0]).unwrap_err(), SealBoxError::UnsealFailed));
    }

    #[test]
    fn test_sealbox_seal() {
        let test_data = TestData { message: "Test message".to_string(), number: 123, flag: false };

        let mut sealbox = SealBox::new(test_data, 2, 3).unwrap();

        sealbox.seal();

        assert!(!sealbox.is_unsealed());
        assert!(sealbox.get().is_err());

        sealbox.seal();

        assert!(!sealbox.is_unsealed());
        assert!(sealbox.get().is_err());
    }

    #[test]
    fn test_sealbox_already_unsealed() {
        let test_data = TestData { message: "Test message".to_string(), number: 123, flag: false };

        let mut sealbox = SealBox::new(test_data, 2, 3).unwrap();
        let shares = sealbox.get_shares().unwrap().clone();

        assert!(matches!(sealbox.unseal(&shares[0]).unwrap_err(), SealBoxError::NotSealed));
        assert!(matches!(sealbox.unseal(&shares[1]).unwrap_err(), SealBoxError::NotSealed));

        assert!(sealbox.is_unsealed());

        assert!(matches!(sealbox.unseal(&shares[2]).unwrap_err(), SealBoxError::NotSealed));
    }

    #[test]
    fn test_sealbox_get_mut() {
        let test_data = TestData { message: "Original message".to_string(), number: 100, flag: true };

        let mut sealbox = SealBox::new(test_data, 2, 3).unwrap();

        {
            let data = sealbox.get_mut().unwrap();
            data.message = "Modified message".to_string();
            data.number = 200;
        }

        let data = sealbox.get().unwrap();
        assert_eq!(data.message, "Modified message");
        assert_eq!(data.number, 200);
        assert_eq!(data.flag, true);
    }

    #[test]
    fn test_sealbox_complex_data() {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct ComplexData {
            strings: Vec<String>,
            numbers: Vec<i32>,
            nested: Option<Box<ComplexData>>,
        }

        let complex_data = ComplexData {
            strings: vec!["hello".to_string(), "world".to_string()],
            numbers: vec![1, 2, 3, 4, 5],
            nested: Some(Box::new(ComplexData {
                strings: vec!["nested".to_string()],
                numbers: vec![42],
                nested: None,
            })),
        };

        let mut sealbox = SealBox::new(complex_data.clone(), 2, 3).unwrap();
        let shares = sealbox.get_shares().unwrap().clone();

        sealbox.seal();

        assert!(matches!(sealbox.unseal(&shares[0]).unwrap_err(), SealBoxError::Unsealing));
        assert!(sealbox.unseal(&shares[1]).is_ok());

        let retrieved_data = sealbox.get().unwrap();
        assert_eq!(*retrieved_data, complex_data);
    }

    #[test]
    fn test_sealbox_edge_cases() {
        let empty_data = TestData { message: "".to_string(), number: 0, flag: false };

        assert!(matches!(SealBox::new(empty_data.clone(), 1, 1), Err(SealBoxError::ShamirSecretSplitFailed)));
        assert!(matches!(SealBox::new(empty_data.clone(), 2, 1), Err(SealBoxError::ShamirSecretSplitFailed)));
        assert!(matches!(SealBox::new(empty_data.clone(), 1, 2), Err(SealBoxError::ShamirSecretSplitFailed)));

        assert!(SealBox::new(empty_data.clone(), 2, 2).is_ok());
        assert!(SealBox::new(empty_data.clone(), 3, 3).is_ok());
    }

    #[test]
    fn test_sealbox_serialization() {
        let test_data = TestData { message: "Serialization test".to_string(), number: 42, flag: true };

        let mut sealbox = SealBox::new(test_data.clone(), 2, 3).unwrap();

        sealbox.seal();

        let serialized = serde_json::to_string(&sealbox).unwrap();
        assert!(!serialized.is_empty());

        let deserialized: SealBox<TestData> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.threshold, sealbox.threshold);
        assert_eq!(deserialized.sealed_data, sealbox.sealed_data);
        assert_eq!(deserialized.nonce, sealbox.nonce);
        assert_eq!(deserialized.aad, sealbox.aad);
        assert_eq!(deserialized.tag, sealbox.tag);

        assert!(deserialized.shares.is_none());
        assert!(deserialized.key.is_none());
        assert!(deserialized.value.is_none());
    }
}
