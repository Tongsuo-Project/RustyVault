use as_any::AsAny;

use crate::{core::Core, errors::RvError};

pub mod auth;
pub mod credential;
pub mod kv;
pub mod pki;
pub mod system;

pub trait Module: AsAny + Send + Sync {
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
