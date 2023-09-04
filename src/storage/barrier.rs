use crate::errors::RvError;
use super::Storage;

pub const BARRIER_INIT_PATH: &str = "barrier/init";

pub trait SecurityBarrier: Storage {
    fn initialized(&self) -> Result<bool, RvError>;
    fn initialize(&mut self, key: &[u8]) -> Result<(), RvError>;
    fn generate_key(&self) -> Result<Vec<u8>, RvError>;
    fn key_length_range(&self) -> (usize, usize);
    fn sealed(&self) -> Result<bool, RvError>;
    fn unseal(&mut self, key: &[u8]) -> Result<(), RvError>;
    fn seal(&mut self) -> Result<(), RvError>;
}
