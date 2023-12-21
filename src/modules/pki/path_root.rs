use std::{
    collections::HashMap,
    sync::Arc,
};

use serde_json::{json, Value};

use super::{util, field, PkiBackend, PkiBackendInner};
use crate::{
    errors::RvError,
    logical::{
        Backend, Operation, Path, PathOperation, Request, Response,
    },
    new_path, new_path_internal,
    utils,
};

impl PkiBackend {
    pub fn root_generate_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let mut path = new_path!({
            pattern: r"root/generate",
            operations: [
                {op: Operation::Write, handler: pki_backend_ref.generate_root}
            ],
            help: "Generate a new CA certificate and private key used for signing."
        });

        path.fields.extend(field::ca_common_fields());
        path.fields.extend(field::ca_key_generation_fields());
        path.fields.extend(field::ca_issue_fields());

        path
    }

    pub fn root_delete_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"root",
            operations: [
                {op: Operation::Delete, handler: pki_backend_ref.delete_root}
            ],
            help: "Deletes the root CA key to allow a new one to be generated."
        });

        path
    }
}

impl PkiBackendInner {
    pub fn generate_root(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut export_private_key = false;
        if req.path.ends_with("/exported") {
            export_private_key = true;
        }

        let role_entry = util::get_role_params(req)?;

        let mut cert = util::generate_certificate(&role_entry, req)?;

        cert.is_ca = true;

        let cert_bundle = cert.to_cert_bundle(None, None)?;

        self.store_ca_bundle(req, &cert_bundle)?;

        let cert_expiration = utils::asn1time_to_timestamp(cert_bundle.certificate.not_after().to_string().as_str())?;

        let mut resp_data = json!({
            "expiration": cert_expiration,
            "issuing_ca": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "certificate": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "serial_number": cert_bundle.serial_number.clone(),
        })
        .as_object()
        .unwrap()
        .clone();

        if export_private_key {
            resp_data.insert("private_key".to_string(),
                             Value::String(String::from_utf8_lossy(&cert_bundle.private_key.private_key_to_pem_pkcs8()?).to_string()));
            resp_data.insert("private_key_type".to_string(),
                             Value::String(cert_bundle.private_key_type.clone()));
        }

        Ok(Some(Response::data_response(Some(resp_data))))
    }

    pub fn delete_root(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        self.delete_ca_bundle(req)?;
        Ok(None)
    }
}
