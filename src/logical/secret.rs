use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{lease::Lease, Backend, Request, Response};
use crate::errors::RvError;

type SecretOperationHandler = dyn Fn(&dyn Backend, &mut Request) -> Result<Option<Response>, RvError> + Send + Sync;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    #[serde(flatten)]
    pub lease: Lease,
    pub lease_id: String,
    #[serde(skip)]
    pub internal_data: Map<String, Value>,
}

pub struct Secret {
    pub secret_type: String,
    pub default_duration: Duration,
    pub renew_handler: Option<Arc<SecretOperationHandler>>,
    pub revoke_handler: Option<Arc<SecretOperationHandler>>,
}

impl Deref for SecretData {
    type Target = Lease;

    fn deref(&self) -> &Lease {
        &self.lease
    }
}

impl DerefMut for SecretData {
    fn deref_mut(&mut self) -> &mut Lease {
        &mut self.lease
    }
}

impl Secret {
    pub fn renewable(&self) -> bool {
        self.renew_handler.is_some()
    }

    pub fn response(&self, data: Option<Map<String, Value>>, internal: Option<Map<String, Value>>) -> Response {
        let mut lease = Lease::default();
        lease.ttl = self.default_duration;
        lease.renewable = self.renewable();

        let mut secret = SecretData { lease, lease_id: String::new(), internal_data: Map::new() };

        if internal.is_some() {
            secret.internal_data = internal.as_ref().unwrap().clone();
        }

        secret.internal_data.insert("secret_type".to_owned(), Value::String(self.secret_type.clone()));

        let mut resp = Response::default();
        resp.data = data;
        resp.secret = Some(secret);
        resp
    }

    pub fn renew(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if !self.renewable() || self.renew_handler.is_none() {
            return Err(RvError::ErrLogicalOperationUnsupported);
        }

        (self.renew_handler.as_ref().unwrap())(backend, req)
    }

    pub fn revoke(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if self.revoke_handler.is_none() {
            return Err(RvError::ErrLogicalOperationUnsupported);
        }

        (self.revoke_handler.as_ref().unwrap())(backend, req)
    }
}

#[macro_export]
macro_rules! new_secret {
    ($($tt:tt)*) => {
        new_secret_internal!($($tt)*)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! new_secret_internal {
    (@object $object:ident () {}) => {
    };
    (@object $object:ident () {secret_type: $secret_type:expr, $($rest:tt)*}) => {
        $object.secret_type = $secret_type.to_string();
        new_secret_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {default_duration: $duration:expr, $($rest:tt)*}) => {
        $object.default_duration = Duration::new($duration, 0);
        new_secret_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {renew_handler: $handler_obj:ident$(.$handler_method:ident)*, $($rest:tt)*}) => {
        $object.renew_handler = Some(Arc::new(move |backend: &dyn Backend, req: &mut Request| -> Result<Option<Response>, RvError> {
            $handler_obj$(.$handler_method)*(backend, req)
        }));
        new_secret_internal!(@object $object () {$($rest)*});
    };
    (@object $object:ident () {revoke_handler: $handler_obj:ident$(.$handler_method:ident)*, $($rest:tt)*}) => {
        $object.revoke_handler = Some(Arc::new(move |backend: &dyn Backend, req: &mut Request| -> Result<Option<Response>, RvError> {
            $handler_obj$(.$handler_method)*(backend, req)
        }));
        new_secret_internal!(@object $object () {$($rest)*});
    };
    ({ $($tt:tt)+ }) => {
        {
            let mut secret = Secret {
                secret_type: String::new(),
                default_duration: Duration::new(0, 0),
                renew_handler: None,
                revoke_handler: None,
            };
            new_secret_internal!(@object secret () {$($tt)+});
            secret
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    struct MyTest;

    impl MyTest {
        pub fn new() -> Self {
            MyTest
        }

        pub fn noop(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
            Ok(None)
        }
    }

    pub fn noop(_backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    #[test]
    fn test_logical_secret() {
        let t = MyTest::new();

        let secret: Secret = new_secret!({
            secret_type: "kv",
            default_duration: 60,
            renew_handler: t.noop,
            revoke_handler: noop,
        });

        assert_eq!(&secret.secret_type, "kv");
        assert_eq!(secret.default_duration, Duration::new(60, 0));
        assert!(secret.renew_handler.is_some());
        assert!(secret.revoke_handler.is_some());
    }
}
