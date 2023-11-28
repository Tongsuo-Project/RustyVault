use super::PkiBackendInner;
use crate::{
    errors::RvError,
    logical::{Backend, Request, Response},
};

impl PkiBackendInner {
    pub fn read_path_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn write_path_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}
