use openssl::{
    x509::{X509},
    pkey::{PKey, Id},
};
use pem;
use crate::{
    utils::cert,
    utils::cert::CertBundle,
    logical::{
        Backend, Request, Response,
    },
    storage::{StorageEntry},
    errors::RvError,
};
use super::{
    PkiBackendInner,
};

impl PkiBackendInner {
    pub fn write_path_ca(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let pem_bundle_value = req.get_data("pem_bundle").expect("pem_bundle not found");
        let pem_bundle = pem_bundle_value.as_str().unwrap();

		let items = pem::parse_many(pem_bundle).expect("Failed to parse PEM bundle");
        let mut key_found = false;
        let mut i = 0;

        let mut cert_bundle = CertBundle::default();

        for item in items {
            if item.tag() == "CERTIFICATE" {
                let cert = X509::from_der(item.contents())?;
                if !cert::is_ca_cert(&cert) {
                    return Err(RvError::ErrPkiPemBundleInvalid);
                }

                if i == 0 {
                    cert_bundle.certificate = cert;
                } else {
                    cert_bundle.ca_chain.push(cert);
                }
                i += 1;
            }
            if item.tag() == "PRIVATE KEY" {
                if key_found {
                    return Err(RvError::ErrPkiPemBundleInvalid);
                }

                let key = PKey::private_key_from_der(item.contents())?;
                match key.id() {
                    Id::RSA => {
                        cert_bundle.private_key_type = "rsa".to_string();
                    },
                    Id::EC => {
                        cert_bundle.private_key_type = "ec".to_string();
                    },
                    Id::SM2 => {
                        cert_bundle.private_key_type = "sm2".to_string();
                    },
                    Id::ED25519 => {
                        cert_bundle.private_key_type = "ed25519".to_string();
                    },
                    _ => {
                        cert_bundle.private_key_type = "other".to_string();
                    }
                }
                cert_bundle.private_key = key;
                key_found = true;
            }
        }

        cert_bundle.verify()?;

        let mut entry = StorageEntry::new("config/ca_bundle", &cert_bundle)?;

        req.storage_put(&entry)?;

        entry.key = "ca".to_string();
        entry.value = cert_bundle.certificate.to_pem().unwrap();
        req.storage_put(&entry)?;

        entry.key = "crl".to_string();
        entry.value = Vec::new();
        req.storage_put(&entry)?;

        Ok(None)
    }

    pub fn fetch_ca_info(&self, req: &Request) -> Result<CertBundle, RvError> {
        let entry = req.storage_get("config/ca_bundle")?;
        if entry.is_none() {
            return Err(RvError::ErrPkiCaNotConfig);
        }

        let cert_bundle: CertBundle = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        Ok(cert_bundle)
    }
}
