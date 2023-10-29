# RustyVault

## Overview

RustyVault is a modern secret management system, written in Rust. RustyVault provides various features which support many scenarios including secure sotrage, cloud identity management, secret management, Kubernetes integration, PKI infrastructure, cryptographic computing, traditional key management, etc.

RustyVault can be deployed in either cloud or physical environments. Depending on different requirements, RustyVault may run as standalone application with a set of RESTful APIs provided, and it can also be used as crate thus you can easily integrate it into your own Rust application.

The core cryptographic module which provides cryptography functionality to RustVault is the [Tongsuo](https://github.com/Tongsuo-Project/Tongsuo) project.

The RustyVault is a subproject of [Tongsuo Project](https://github.com/Tongsuo-Project).

## Feature

* API
  * RESTful API fully compatible with Hashicorp Vault
* Authentication & Authorization
  * AuthN based on certificate
  * AuthN based on username/password
  * Basic ACL
* Secure Storage
  * Local storage
  * Remote storage
* Configuration
  * HCL compatible
* PKI/CA infrastructure
  * X.509 certificate signing: RSA/ECC/SM2
  * X.509 certificate revocation: OCSP, CRL
* Key management
  * Symmetric key: create/rotate/store
  * Public key: RSA/ECC/SM2
* Cryptographic Algorithm
  * Symmetric: AES, SM4
  * Public Key:
      * Signature: RSA/ECDSA/EdDSA/SM2
      * Encryption: RSA/SM2
  * Hash: SHA1/SHA2/SM3
  * PRNG
* Cryptographic Computing
  * PHE: Paillier, EC-ElGamal
  * ZKP: Bulletproofs
* Hareware Support
  * Cryptography acceleration hardware
  * Cryptography key management hardware (HSM or so)
    * TEE
* Cluster & HA
  * Active - Active
* Log & Audit
  * Log to file

## Design

Read the [design](.\/design.md) document.
