//! The `rusty_vault::handler` module basically defines the `Handler` trait.
//!
//! The `Handler` trait includes a set of 'hook points' that are performed during the process of an
//! API request from the user.
//!
//! The `Handler` trait should be implemented in other module, such as the `rusty_vault::router`
//! for instance.

use crate::{
    errors::RvError,
    logical::{request::Request, response::Response},
};

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
