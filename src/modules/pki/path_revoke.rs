use crate::{
    logical::{
        Backend, Request, Response,
    },
    errors::RvError,
};
use super::{
    PkiBackendInner,
};

impl PkiBackendInner {
    pub fn revoke_cert(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn read_rotate_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

