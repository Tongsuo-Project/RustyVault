use crate::errors::RvError;
use super::Storage;

pub const BARRIER_INIT_PATH: &str = "barrier/init";

pub trait SecurityBarrier: Storage + Send + Sync {
    fn inited(&self) -> Result<bool, RvError>;
    fn init(&self, key: &[u8]) -> Result<(), RvError>;
    fn generate_key(&self) -> Result<Vec<u8>, RvError>;
    fn key_length_range(&self) -> (usize, usize);
    fn sealed(&self) -> Result<bool, RvError>;
    fn unseal(&self, key: &[u8]) -> Result<(), RvError>;
    fn seal(&self) -> Result<(), RvError>;
    fn as_storage(&self) -> &dyn Storage;
}
