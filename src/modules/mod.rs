use as_any::{AsAny};
use crate::core::Core;
use crate::errors::RvError;

pub mod kv;
pub mod system;
pub mod auth;

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
