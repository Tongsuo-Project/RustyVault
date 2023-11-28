use super::PkiBackendInner;
use crate::{
    errors::RvError,
    logical::{Backend, Request, Response},
};

impl PkiBackendInner {
    pub fn revoke_cert(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn read_rotate_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}
