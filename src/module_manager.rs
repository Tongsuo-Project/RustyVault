use crate::core::Core;
use crate::modules::Module;
use crate::modules::kv::KvModule;
use crate::modules::system::SystemModule;
use crate::errors::RvError;

pub struct ModuleManager {
    pub modules: Vec<Box<dyn Module>>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            modules: vec![
                Box::new(KvModule::new()),
                Box::new(SystemModule::new())
            ],
        }
    }

    pub fn init(&self, core: &Core) -> Result<(), RvError> {
        for module in &self.modules {
            module.init(core)?
        }

        Ok(())
    }
}
