use crate::errors::RvError;
use crate::logical::request::Request;
use crate::logical::response::Response;

pub trait Handler {
    fn pre_route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    fn route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    fn post_route(&self, _req: &mut Request, _resp: &mut Response) -> Result<(), RvError> {
        Ok(())
    }

    fn log(&self, _req: &Request, _resp: &Response) -> Result<(), RvError> {
        Ok(())
    }
}

