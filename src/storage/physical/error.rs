use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("Backend etcd error: {0}!")]
    EtcdError(String),
}
