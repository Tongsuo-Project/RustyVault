use std::{
    sync::Arc,
    collections::HashMap,
};

use super::{PkiBackend, PkiBackendInner};
use crate::{
    errors::RvError,
    logical::{
        Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response,
    },
    new_path, new_path_internal, new_fields, new_fields_internal,
};

impl PkiBackend {
    pub fn revoke_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: "revoke",
            fields: {
                "serial_number": {
                    field_type: FieldType::Str,
                    description: "Certificate serial number, in colon- or hyphen-separated octal"
                }
            },
            operations: [
                {op: Operation::Write, handler: pki_backend_ref.revoke_cert}
            ],
            help: r#"
This allows certificates to be revoked using its serial number. A root token is required.
                "#
        });

        path
    }

    pub fn crl_rotate_path(&self) -> Path {
        let pki_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: "crl/rotate",
            operations: [
                {op: Operation::Read, handler: pki_backend_ref.read_rotate_crl}
            ],
            help: r#"
Force a rebuild of the CRL. This can be used to remove expired certificates from it if no certificates have been revoked. A root token is required.
                "#
        });

        path
    }
}

impl PkiBackendInner {
    pub fn revoke_cert(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn read_rotate_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}
