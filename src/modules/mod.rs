//! `rusty_vault::modules` contains a set of real RustyVault modules. Each sub module needs to
//! implement the `rusty_vault::modules::Module` trait defined here and then the module
//! could be added to module manager.
//!
//! It's important for the developers who want to implement a new RustyVault module themselves to
//! get the `trait Module` implemented correctly.

use as_any::AsAny;

use crate::{core::Core, errors::RvError};

pub mod auth;
pub mod credential;
pub mod crypto;
pub mod kv;
pub mod pki;
pub mod policy;
pub mod system;

pub trait Module: AsAny + Send + Sync {
    //! Description for a trait itself.
    fn name(&self) -> String;
    fn init(&mut self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn setup(&mut self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn cleanup(&mut self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }
}
