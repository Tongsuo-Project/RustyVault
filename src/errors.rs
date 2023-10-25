use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RvError {
    #[error("Core logical backend already exists.")]
    ErrCoreLogicalBackendExist,
    #[error("Core logical backend does not exist.")]
    ErrCoreLogicalBackendNoExist,
    #[error("Core router not handling.")]
    ErrCoreRouterNotHandling,
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
    #[error("Logical backend path not supported.")]
    ErrLogicalPathUnsupported,
    #[error("Request is not ready.")]
    ErrRequestNotReady,
    #[error("Module kv data field is missing.")]
    ErrModuleKvDataFieldMissing,
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
    #[error("Some regex error happened, {:?}", .source)]
    Regex {
        #[from]
        source: regex::Error
    },
    #[error(transparent)]
    ErrOther (#[from] anyhow::Error),
    #[error("Unknown error.")]
    ErrUnknown,
}

impl PartialEq for RvError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RvError::ErrCoreLogicalBackendExist, RvError::ErrCoreLogicalBackendExist)
            | (RvError::ErrCoreLogicalBackendNoExist, RvError::ErrCoreLogicalBackendNoExist)
            | (RvError::ErrPhysicalConfigItemMissing, RvError::ErrPhysicalConfigItemMissing)
            | (RvError::ErrPhysicalTypeInvalid, RvError::ErrPhysicalTypeInvalid)
            | (RvError::ErrPhysicalBackendPrefixInvalid, RvError::ErrPhysicalBackendPrefixInvalid)
            | (RvError::ErrPhysicalBackendKeyInvalid, RvError::ErrPhysicalBackendKeyInvalid)
            | (RvError::ErrBarrierKeySanityCheckFailed, RvError::ErrBarrierKeySanityCheckFailed)
            | (RvError::ErrBarrierAlreadyInit, RvError::ErrBarrierAlreadyInit)
            | (RvError::ErrBarrierKeyInvalid, RvError::ErrBarrierKeyInvalid)
            | (RvError::ErrBarrierNotInit, RvError::ErrBarrierNotInit)
            | (RvError::ErrBarrierSealed, RvError::ErrBarrierSealed)
            | (RvError::ErrBarrierEpochMismatch, RvError::ErrBarrierEpochMismatch)
            | (RvError::ErrBarrierVersionMismatch, RvError::ErrBarrierVersionMismatch)
            | (RvError::ErrBarrierKeyGenerationFailed, RvError::ErrBarrierKeyGenerationFailed)
            | (RvError::ErrRouterMountConflict, RvError::ErrRouterMountConflict)
            | (RvError::ErrRouterMountNotFound, RvError::ErrRouterMountNotFound)
            | (RvError::ErrMountPathProtected, RvError::ErrMountPathProtected)
            | (RvError::ErrMountPathExist, RvError::ErrMountPathExist)
            | (RvError::ErrMountTableNotFound, RvError::ErrMountTableNotFound)
            | (RvError::ErrMountTableNotReady, RvError::ErrMountTableNotReady)
            | (RvError::ErrMountNotMatch, RvError::ErrMountNotMatch)
            | (RvError::ErrCoreRouterNotHandling, RvError::ErrCoreRouterNotHandling)
            | (RvError::ErrRequestNotReady, RvError::ErrRequestNotReady)
            | (RvError::ErrModuleKvDataFieldMissing, RvError::ErrModuleKvDataFieldMissing)
            | (RvError::ErrUnknown, RvError::ErrUnknown)
            => true,
            _ => false,
        }
    }
}
