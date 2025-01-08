//! The `rusty_vault::handler` module basically defines the `Handler` trait.
//!
//! The `Handler` trait includes a set of 'hook points' that are performed during the process of an
//! API request from the user.
//!
//! The `Handler` trait should be implemented in other module, such as the `rusty_vault::router`
//! for instance.

use derive_more::Display;
use async_trait::async_trait;

use crate::{
    core::Core,
    cli::config::Config,
    errors::RvError,
    logical::{request::Request, response::Response, Auth},
};

#[async_trait]
pub trait Handler: Send + Sync {
    fn name(&self) -> String;

    fn post_config(&self, _core: &mut Core, _config: Option<&Config>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    async fn pre_route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    async fn route(&self, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    async fn post_route(&self, _req: &mut Request, _resp: &mut Option<Response>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    async fn log(&self, _req: &Request, _resp: &Option<Response>) -> Result<(), RvError> {
        Err(RvError::ErrHandlerDefault)
    }
}

#[async_trait]
pub trait AuthHandler: Send + Sync {
    fn name(&self) -> String;

    async fn pre_auth(&self, _req: &mut Request) -> Result<Option<Auth>, RvError> {
        Err(RvError::ErrHandlerDefault)
    }

    async fn post_auth(&self, _req: &mut Request) -> Result<(), RvError> {
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
