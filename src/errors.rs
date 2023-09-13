use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RvError {
    #[error("Core logical backend already exists.")]
    ErrCoreLogicalBackendExist,
    #[error("Core logical backend does not exist.")]
    ErrCoreLogicalBackendNoExist,
    #[error("Physical configuration item is missing.")]
    ErrPhysicalConfigItemMissing,
    #[error("Physical type is invalid.")]
    ErrPhysicalTypeInvalid,
    #[error("Physical backend prefix is invalid.")]
    ErrPhysicalBackendPrefixInvalid,
    #[error("Physical backend key is invalid.")]
    ErrPhysicalBackendKeyInvalid,
    #[error("Barrier key sanity check failed.")]
    ErrBarrierKeySanityCheckFailed,
    #[error("Barrier has been initialized.")]
    ErrBarrierAlreadyInit,
    #[error("Barrier key is invalide.")]
    ErrBarrierKeyInvalid,
    #[error("Barrier is not initialized.")]
    ErrBarrierNotInit,
    #[error("Barrier has been sealed.")]
    ErrBarrierSealed,
    #[error("Barrier epoch do not match.")]
    ErrBarrierEpochMismatch,
    #[error("Barrier version do not match.")]
    ErrBarrierVersionMismatch,
    #[error("Barrier key generation failed.")]
    ErrBarrierKeyGenerationFailed,
    #[error("Router mount conflict.")]
    ErrRouterMountConflict,
    #[error("Router mount not found.")]
    ErrRouterMountNotFound,
    #[error("Mount path is protected, cannot mount.")]
    ErrMountPathProtected,
    #[error("Mount path already exists.")]
    ErrMountPathExist,
    #[error("Mount table not found.")]
    ErrMountTableNotFound,
    #[error("Mount table is not ready.")]
    ErrMountTableNotReady,
    #[error("Mount not match.")]
    ErrMountNotMatch,
    #[error("Some IO error happened, {:?}", .source)]
    IO {
        #[from]
        source: io::Error
    },
    #[error("Some serde error happened, {:?}", .source)]
    Serde {
        #[from]
        source: serde_json::Error
    },
    #[error("Some openssl error happened, {:?}", .source)]
    OpenSSL {
        #[from]
        source: openssl::error::ErrorStack
    },
    #[error(transparent)]
    ErrOther (#[from] anyhow::Error),
    #[error("Unknown error.")]
    ErrUnknown,
}
