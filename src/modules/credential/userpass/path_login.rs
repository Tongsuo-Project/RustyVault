use std::{collections::HashMap, sync::Arc};

use super::{UserPassBackend, UserPassBackendInner};
use crate::{
    errors::RvError,
    logical::{Auth, Backend, Field, FieldType, Lease, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

impl UserPassBackend {
    pub fn login_path(&self) -> Path {
        let userpass_backend_ref = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"login/(?P<username>\w[\w-]+\w)",
            fields: {
                "username": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Username of the user."
                },
                "password": {
                    field_type: FieldType::SecretStr,
                    required: true,
                    description: "Password for this user."
                }
            },
            operations: [
                {op: Operation::Write, handler: userpass_backend_ref.login}
            ],
            help: r#"This endpoint authenticates using a username and password."#
        });

        path
    }
}

impl UserPassBackendInner {
    pub fn login(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let err_info = "invalid username or password";
        let username_value = req.get_data("username")?;
        let username = username_value.as_str().unwrap().to_lowercase();
        let password_value = req.get_data("password")?;
        let password = password_value.as_str().unwrap();

        let user = self.get_user(req, &username)?;
        if user.is_none() {
            log::error!("{}", err_info);
            let resp = Response::error_response(&err_info);
            return Ok(Some(resp));
        }

        let user = user.unwrap();

        let check = self.verify_password_hash(password, &user.password_hash)?;
        if !check {
            log::error!("{}", err_info);
            let resp = Response::error_response(&err_info);
            return Ok(Some(resp));
        }

        let mut auth = Auth {
            lease: Lease {
                ttl: user.ttl,
                max_ttl: user.max_ttl,
                renewable: user.ttl.as_secs() > 0,
                ..Default::default()
            },
            display_name: username.to_string(),
            policies: user.policies.clone(),
            ..Default::default()
        };
        auth.metadata.insert("username".to_string(), username.to_string());
        let resp = Response { auth: Some(auth), ..Response::default() };

        Ok(Some(resp))
    }
}
