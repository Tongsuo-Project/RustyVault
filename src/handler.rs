//! The `rusty_vault::handler` module basically defines the `Handler` trait.
//!
//! The `Handler` trait includes a set of 'hook points' that are performed during the process of an
//! API request from the user.
//!
//! The `Handler` trait should be implemented in other module, such as the `rusty_vault::router`
//! for instance.

use std::sync::{Arc, RwLock};

use derive_more::Display;

use crate::{
    core::Core,
    cli::config::Config,
    errors::RvError,
    logical::{request::Request, response::Response, Auth},
};

pub trait Handler: Send + Sync {
    fn name(&self) -> String;

    fn post_config(&self, _core: Arc<RwLock<Core>>, _config: Option<&Config>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }

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

pub trait AuthHandler: Send + Sync {
    fn name(&self) -> String;

    fn pre_auth(&self, _req: &mut Request) -> Result<Option<Auth>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    fn post_auth(&self, _req: &mut Request) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }
}

#[derive(Display, Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandlePhase {
    #[display(fmt = "pre_auth")]
    PreAuth,
    #[display(fmt = "post_auth")]
    PostAuth,
    #[display(fmt = "pre_route")]
    PreRoute,
    #[display(fmt = "route")]
    Route,
    #[display(fmt = "post_route")]
    PostRoute,
    #[display(fmt = "log")]
    Log,
}