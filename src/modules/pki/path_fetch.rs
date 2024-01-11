use std::{collections::HashMap, sync::Arc};

use openssl::x509::X509;
use serde_json::json;

use super::{PkiBackend, PkiBackendInner};
use crate::{
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
    utils::cert::CertBundle,
};

impl PkiBackend {
    pub fn fetch_ca_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: "ca(/pem)?",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_ca}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_crl_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: "crl(/pem)?",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_crl}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_cert_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"cert/(?P<serial>[0-9A-Fa-f-:]+)",
            fields: {
                "serial": {
                    field_type: FieldType::Str,
                    default: "72h",
                    description: "Certificate serial number, in colon- or hyphen-separated octal"
                }
            },
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_cert}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }

    pub fn fetch_cert_crl_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: "cert/crl",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_path_fetch_cert_crl}
            ],
            help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                "#
        });

        path
    }
}

impl PkiBackendInner {
    pub fn handle_fetch_cert_bundle(&self, cert_bundle: &CertBundle) -> Result<Option<Response>, RvError> {
        let ca_chain_pem: String = cert_bundle
            .ca_chain
            .iter()
            .rev()
            .map(|x509| x509.to_pem().unwrap())
            .map(|pem| String::from_utf8_lossy(&pem).to_string())
            .collect::<Vec<String>>()
            .join("");
        let resp_data = json!({
            "ca_chain": ca_chain_pem,
            "certificate": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "serial_number": cert_bundle.serial_number.clone(),
        })
        .as_object()
        .unwrap()
        .clone();

        Ok(Some(Response::data_response(Some(resp_data))))
    }

    pub fn read_path_fetch_ca(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let ca_bundle = self.fetch_ca_bundle(req)?;
        self.handle_fetch_cert_bundle(&ca_bundle)
    }

    pub fn read_path_fetch_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn read_path_fetch_cert(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let serial_number_value = req.get_data("serial")?;
        let serial_number = serial_number_value.as_str().unwrap();
        let serial_number_hex = serial_number.replace(":", "-").to_lowercase();
        let cert = self.fetch_cert(req, &serial_number_hex)?;
        let ca_bundle = self.fetch_ca_bundle(req)?;

        let mut ca_chain_pem: String = ca_bundle
            .ca_chain
            .iter()
            .rev()
            .map(|x509| x509.to_pem().unwrap())
            .map(|pem| String::from_utf8_lossy(&pem).to_string())
            .collect::<Vec<String>>()
            .join("");

        ca_chain_pem = ca_chain_pem + &String::from_utf8_lossy(&ca_bundle.certificate.to_pem().unwrap());

        let resp_data = json!({
            "ca_chain": ca_chain_pem,
            "certificate": String::from_utf8_lossy(&cert.to_pem()?),
            "serial_number": serial_number,
        })
        .as_object()
        .unwrap()
        .clone();

        Ok(Some(Response::data_response(Some(resp_data))))
    }

    pub fn read_path_fetch_cert_crl(
        &self,
        _backend: &dyn Backend,
        _req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn fetch_cert(&self, req: &Request, serial_number: &str) -> Result<X509, RvError> {
        let entry = req.storage_get(format!("certs/{}", serial_number).as_str())?;
        if entry.is_none() {
            return Err(RvError::ErrPkiCertNotFound);
        }

        let cert: X509 = X509::from_der(entry.unwrap().value.as_slice())?;
        Ok(cert)
    }

    pub fn store_cert(&self, req: &Request, serial_number: &str, cert: &X509) -> Result<(), RvError> {
        let value = cert.to_der()?;
        let entry = StorageEntry { key: format!("certs/{}", serial_number), value };
        req.storage_put(&entry)?;
        Ok(())
    }

    pub fn delete_cert(&self, req: &Request, serial_number: &str) -> Result<(), RvError> {
        req.storage_delete(format!("certs/{}", serial_number).as_str())?;
        Ok(())
    }
}
