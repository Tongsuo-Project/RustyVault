use crate::errors::RvError;
use crate::logical::request::Request;
use crate::logical::response::Response;

pub trait Handler: Send + Sync {
    fn name(&self) -> String;

    fn pre_route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    fn route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    fn post_route(&self, _req: &mut Request, _resp: &mut Option<Response>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    fn log(&self, _req: &Request, _resp: &Option<Response>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }
}

