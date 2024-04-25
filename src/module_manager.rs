//! RustyVault is consisted of many modules. Modules are the real components that implement the
//! features that users need. All modules in RustyVault are managed by `rusty_vault::module_manager`.
//!
//! In details, the module manager is able to organize, add, remove, setup, initialize, cleanup
//! other RustyVault modules.
//!
//! Do not mix up the RustyVault module with the concept of a Rust module. A RustyVault module is a
//! piece of code that implements some functionality. Although usually that piece of code is
//! organized in the form of a module of crate `rusty_vault` in Rust language concept.

use std::sync::{Arc, RwLock};

use crate::{
    core::Core,
    errors::RvError,
    modules::{kv::KvModule, system::SystemModule, Module},
};

pub struct ModuleManager {
    pub modules: Vec<Arc<RwLock<Box<dyn Module>>>>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    pub fn set_default_modules(&mut self, core: Arc<RwLock<Core>>) -> Result<(), RvError> {
        self.modules = vec![
            Arc::new(RwLock::new(Box::new(KvModule::new(Arc::clone(&core))))),
            Arc::new(RwLock::new(Box::new(SystemModule::new(core)))),
        ];
        Ok(())
    }

    pub fn get_module(&self, name: &str) -> Option<Arc<RwLock<Box<dyn Module>>>> {
        for it in &self.modules {
            let m = it.read().unwrap();
            if m.name().as_str() == name {
                return Some(Arc::clone(&it));
            }
        }

        None
    }

    pub fn add_module(&mut self, module: Arc<RwLock<Box<dyn Module>>>) -> Result<(), RvError> {
        {
            let m = module.read()?;
            if self.get_module(m.name().as_str()).is_some() {
                return Err(RvError::ErrModuleConflict);
            }
        }

        self.modules.push(module);
        Ok(())
    }

    pub fn remove_module(&mut self, name: &str) -> Result<(), RvError> {
        self.modules.retain(|m| m.read().unwrap().name().as_str() != name);
        Ok(())
    }

    pub fn setup(&self, core: &Core) -> Result<(), RvError> {
        for module in &self.modules {
            let mut m = module.write()?;
            m.setup(core)?
        }

        Ok(())
    }

    pub fn init(&self, core: &Core) -> Result<(), RvError> {
        for module in &self.modules {
            let mut m = module.write()?;
            m.init(core)?
        }

        Ok(())
    }

    pub fn cleanup(&self, core: &Core) -> Result<(), RvError> {
        for module in &self.modules {
            let mut m = module.write()?;
            m.cleanup(core)?
        }

        Ok(())
    }
}
