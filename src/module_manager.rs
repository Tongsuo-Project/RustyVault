use std::{
    sync::{Arc, RwLock},
};
use crate::core::Core;
use crate::modules::Module;
use crate::modules::kv::KvModule;
use crate::modules::system::SystemModule;
use crate::errors::RvError;

pub struct ModuleManager {
    pub modules: Vec<Arc<RwLock<Box<dyn Module>>>>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn set_default_modules(&mut self, core: Arc<RwLock<Core>>) -> Result<(), RvError> {
        self.modules = vec![
            Arc::new(RwLock::new(Box::new(KvModule::new(Arc::clone(&core))))),
            Arc::new(RwLock::new(Box::new(SystemModule::new(core))))
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
