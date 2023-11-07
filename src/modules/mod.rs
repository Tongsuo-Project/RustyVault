use crate::core::Core;
use crate::errors::RvError;

pub mod kv;
pub mod system;

pub trait Module: Send + Sync {
    fn name(&self) -> String;
    fn init(&self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn setup(&self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }

    fn cleanup(&self, _core: &Core) -> Result<(), RvError> {
        Ok(())
    }
}
