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
    pub fn read_path_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn write_path_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}
