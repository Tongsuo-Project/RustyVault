use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::SystemTime,
};

use go_defer::defer;

use super::{
    validation::SecretIdAccessorStorageEntry, AppRoleBackend, AppRoleBackendInner, SECRET_ID_ACCESSOR_LOCAL_PREFIX,
    SECRET_ID_ACCESSOR_PREFIX, SECRET_ID_LOCAL_PREFIX, SECRET_ID_PREFIX,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Operation, Path, PathOperation, Request, Response, CTX_KEY_BACKEND_PATH},
    new_path, new_path_internal,
    storage::Storage,
};

pub const CTX_KEY_BACKEND_PATH_INNER: &str = "backend.path.inner";

impl AppRoleBackend {
    pub fn tidy_secret_id_path(&self) -> Path {
        let approle_backend_ref1 = Arc::clone(&self.inner);
        let approle_backend_ref2 = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"tidy/secret-id$",
            operations: [
                {op: Operation::Write, handler: approle_backend_ref1.tidy_secret_id}
            ],
            help: r#"
SecretIDs will have expiration time attached to them. The periodic function
of the backend will look for expired entries and delete them. This happens once in a minute. Invoking
this endpoint will trigger the clean-up action, without waiting for the backend's periodic function.
"#
        });

        path.ctx.set(CTX_KEY_BACKEND_PATH_INNER, approle_backend_ref2);

        path
    }
}

impl AppRoleBackendInner {
    async fn tidy_secret_id_routine(&self, storage: Arc<dyn Storage>) {
        let check_count = AtomicU32::new(0);

        defer! (
            self.tidy_secret_id_cas_guard.store(0, Ordering::SeqCst);
            log::info!("done checking entries, num_entries: {}", check_count.load(Ordering::SeqCst));
        );

        let salt = self.salt.read();
        if salt.is_err() {
            log::error!("error tidying secret IDs, err: {}", salt.unwrap_err());
            return;
        }

        let salt = salt.unwrap();

        let tidy_func = |secret_id_prefix_to_use: &str, accessor_id_prefix_to_use: &str| -> Result<(), RvError> {
            log::info!("listing accessors, prefix: {}", accessor_id_prefix_to_use);
            // List all the accessors and add them all to a map
            // These hashes are the result of salting the accessor id.
            let accessor_hashes = storage.list(accessor_id_prefix_to_use)?;
            let mut skip_hashes: HashMap<String, bool> = HashMap::new();
            let mut accessor_entry_by_hash: HashMap<String, SecretIdAccessorStorageEntry> = HashMap::new();
            for accessor_hash in accessor_hashes.iter() {
                let entry_index = format!("{}{}", accessor_id_prefix_to_use, accessor_hash);
                let storage_entry = storage.get(&entry_index)?;
                if storage_entry.is_none() {
                    continue;
                }

                let entry = storage_entry.unwrap();
                let ret: SecretIdAccessorStorageEntry = serde_json::from_slice(entry.value.as_slice())?;
                accessor_entry_by_hash.insert(accessor_hash.clone(), ret);
            }

            let mut secret_id_cleanup_func = |secret_id_hmac: &str,
                                              role_name_hmac: &str,
                                              secret_id_prefix_to_use: &str|
             -> Result<(), RvError> {
                check_count.fetch_add(1, Ordering::SeqCst);

                let s = Arc::as_ref(&storage);

                let lock_entry = self.secret_id_locks.get_lock(secret_id_hmac);
                let _locked = lock_entry.lock.write()?;

                let secret_id_storage_entry = self
                    .get_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?
                    .ok_or(RvError::ErrResponse(format!(
                        "entry for secret id was nil, secret_id_hmac: {}",
                        secret_id_hmac
                    )))?;

                // If a secret ID entry does not have a corresponding accessor
                // entry, revoke the secret ID immediately
                if self
                    .get_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )?
                    .is_none()
                {
                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?;
                    return Ok(());
                }

                // ExpirationTime not being set indicates non-expiring SecretIDs
                if SystemTime::now() > secret_id_storage_entry.expiration_time {
                    log::info!("found expired secret ID");
                    // Clean up the accessor of the secret ID first
                    self.delete_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )?;

                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?;

                    return Ok(());
                }

                // At this point, the secret ID is not expired and is valid. Flag
                // the corresponding accessor as not needing attention.
                let salt_id = salt.as_ref().unwrap().salt_id(&secret_id_storage_entry.secret_id_accessor)?;
                skip_hashes.insert(salt_id, true);

                Ok(())
            };

            log::info!("listing role HMACs, prefix: {}", secret_id_prefix_to_use);

            let role_name_hmacs = storage.list(secret_id_prefix_to_use)?;
            for role_name_hmac in role_name_hmacs.iter() {
                log::info!("listing secret id HMACs, role_hame: {}", role_name_hmac);
                let key = format!("{}{}/", secret_id_prefix_to_use, role_name_hmac);
                let secret_id_hmacs = storage.list(&key)?;
                for secret_id_hmac in secret_id_hmacs.iter() {
                    secret_id_cleanup_func(&secret_id_hmac, &role_name_hmac, secret_id_prefix_to_use)?;
                }
            }

            if accessor_hashes.len() > skip_hashes.len() {
                // There is some raciness here because we're querying secretids for
                // roles without having a lock while doing so.  Because
                // accessor_entry_by_hash was populated previously, at worst this may
                // mean that we fail to clean up something we ought to.
                let mut all_secret_id_hmacs: HashMap<String, bool> = HashMap::new();
                for role_name_hmac in role_name_hmacs.iter() {
                    let key = format!("{}{}/", secret_id_prefix_to_use, role_name_hmac);
                    let secret_id_hmacs = storage.list(&key)?;
                    for secret_id_hmac in secret_id_hmacs.iter() {
                        all_secret_id_hmacs.insert(secret_id_hmac.clone(), true);
                    }
                }

                for (accessor_hash, accessor_entry) in accessor_entry_by_hash.iter() {
                    let lock_entry = self.secret_id_locks.get_lock(&accessor_entry.secret_id_hmac);
                    let _locked = lock_entry.lock.write()?;

                    // Don't clean up accessor index entry if secretid cleanup func
                    // determined that it should stay.
                    if skip_hashes.contains_key(accessor_hash) {
                        continue;
                    }

                    // Don't clean up accessor index entry if referenced in role.
                    if all_secret_id_hmacs.contains_key(&accessor_entry.secret_id_hmac) {
                        continue;
                    }

                    let entry_index = format!("{}{}", accessor_id_prefix_to_use, accessor_hash);

                    storage.delete(&entry_index)?;
                }
            }

            Ok(())
        };

        if let Err(err) = tidy_func(SECRET_ID_PREFIX, SECRET_ID_ACCESSOR_PREFIX) {
            log::error!("error tidying global secret IDs, error: {}", err);
            return;
        }

        if let Err(err) = tidy_func(SECRET_ID_LOCAL_PREFIX, SECRET_ID_ACCESSOR_LOCAL_PREFIX) {
            log::error!("error tidying local secret IDs, error: {}", err);
            return;
        }
    }

    pub fn tidy_secret_id(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = Response::new();
        if self.tidy_secret_id_cas_guard.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            resp.add_warning("Tidy operation already in progress");
            return Ok(Some(resp));
        }

        let storage = Arc::clone(req.storage.as_ref().unwrap());

        let ctx = backend.get_ctx().ok_or(RvError::ErrRequestInvalid)?;
        let path: Arc<Path> = ctx
            .get(CTX_KEY_BACKEND_PATH)
            .ok_or(RvError::ErrRequestInvalid)?
            .downcast::<Path>()
            .map_err(|_| RvError::ErrRequestInvalid)?
            .clone();
        let path_inner: Arc<AppRoleBackendInner> = path
            .ctx
            .get(CTX_KEY_BACKEND_PATH_INNER)
            .ok_or(RvError::ErrRequestInvalid)?
            .downcast::<AppRoleBackendInner>()
            .map_err(|_| RvError::ErrRequestInvalid)?
            .clone();

        let task = actix_rt::spawn(async move {
            path_inner.tidy_secret_id_routine(storage).await;
        });

        req.add_task(task);

        resp.set_request_id(&req.id);
        resp.add_warning(
            "Tidy operation successfully started. Any information from the operation will be printed to RustyVault's \
             server logs.",
        );

        let ret = Response::respond_with_status_code(Some(resp), 202);

        Ok(Some(ret))
    }
}

#[cfg(test)]
mod test {
    use std::{
        default::Default,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use actix_rt::System;
    use as_any::Downcast;
    use tokio::runtime::Builder;

    use super::{
        super::{path_role::RoleEntry, AppRoleModule},
        *,
    };
    use crate::{
        logical::{Operation, Request},
        storage::{Storage, StorageEntry},
        test_utils::{test_mount_auth_api, test_rusty_vault_init},
    };

    #[test]
    fn test_approle_tidy_dangling_accessors_normal() {
        let (root_token, core) = test_rusty_vault_init("test_approle_tidy_dangling_accessors_normal");
        let c = core.read().unwrap();

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&c, &root_token, "approle", "approle/");

        let module = c.module_manager.get_module("approle").unwrap();
        let approle_mod = module.read().unwrap();
        let approle_module = approle_mod.as_ref().downcast_ref::<AppRoleModule>().unwrap();

        // Create a role
        let mut req = Request::new("/auth/approle/role1");
        req.operation = Operation::Write;
        req.storage = c.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            secret_id_ttl: Duration::from_secs(300),
            policies: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "");
        assert!(resp.is_ok());

        // Create a secret-id
        req.operation = Operation::Write;
        req.path = "auth/approle/role/role1/secret-id".to_string();
        req.client_token = root_token.to_string();
        let _resp = c.handle_request(&mut req);
        req.storage = c.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let mut mock_backend = approle_module.new_backend();
        assert!(mock_backend.init().is_ok());

        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req);
        assert!(resp.is_ok());

        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());

        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 1);

        let entry = StorageEntry::new(
            "accessor/invalid1",
            &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac".to_string() },
        )
        .unwrap();

        assert!(req.storage_put(&entry).is_ok());

        let entry = StorageEntry::new(
            "accessor/invalid2",
            &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac2".to_string() },
        )
        .unwrap();

        assert!(req.storage_put(&entry).is_ok());

        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 3);

        let rt =
            System::with_tokio_rt(|| Builder::new_multi_thread().worker_threads(128).enable_all().build().unwrap());
        rt.block_on(async {
            req.operation = Operation::Write;
            req.path = "tidy/secret-id".to_string();
            let _resp = mock_backend.handle_request(&mut req);
            actix_rt::System::current().stop();
        });

        let _ = rt.run().unwrap();

        std::thread::sleep(Duration::from_secs(5));

        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), 1);
    }

    #[test]
    fn test_approle_tidy_dangling_accessors_race() {
        let (root_token, core) = test_rusty_vault_init("test_approle_tidy_dangling_accessors_race");
        let c = core.read().unwrap();

        // Mount approle auth to path: auth/approle
        test_mount_auth_api(&c, &root_token, "approle", "approle/");

        let module = c.module_manager.get_module("approle").unwrap();
        let approle_mod = module.read().unwrap();
        let approle_module = approle_mod.as_ref().downcast_ref::<AppRoleModule>().unwrap();

        let mut mock_backend = approle_module.new_backend();
        assert!(mock_backend.init().is_ok());

        // Create a role
        let mut req = Request::new("/auth/approle/role1");
        req.operation = Operation::Write;
        req.storage = c.get_system_view().map(|arc| arc as Arc<dyn Storage>);

        let role_entry = RoleEntry {
            role_id: "testroleid".to_string(),
            hmac_key: "testhmackey".to_string(),
            bind_secret_id: true,
            secret_id_ttl: Duration::from_secs(300),
            policies: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..Default::default()
        };
        let resp = approle_module.set_role(&mut req, "role1", &role_entry, "");
        assert!(resp.is_ok());

        // Create a secret-id
        req.operation = Operation::Write;
        req.path = "auth/approle/role/role1/secret-id".to_string();
        req.client_token = root_token.to_string();
        let _resp = c.handle_request(&mut req);
        req.storage = c.get_system_view().map(|arc| arc as Arc<dyn Storage>);
        let resp = approle_module.write_role_secret_id(&mock_backend, &mut req);
        assert!(resp.is_ok());

        let count = Arc::new(Mutex::new(1));
        let start = Instant::now();
        let core_cloned = core.clone();

        //let invalid_accessors = Arc::new(Mutex::new());

        let rt =
            System::with_tokio_rt(|| Builder::new_multi_thread().worker_threads(128).enable_all().build().unwrap());

        rt.block_on(async {
            while start.elapsed() < Duration::new(5, 0) {
                if start.elapsed() > Duration::from_millis(100)
                    && approle_module.tidy_secret_id_cas_guard.load(Ordering::SeqCst) == 0
                {
                    req.operation = Operation::Write;
                    req.path = "tidy/secret-id".to_string();
                    let _ = mock_backend.handle_request(&mut req);
                }

                let core_cloned2 = core_cloned.clone();
                let token = root_token.clone();
                let mb = mock_backend.clone();

                actix_rt::spawn(async move {
                    let c = core_cloned2.read().unwrap();
                    let module = c.module_manager.get_module("approle").unwrap();
                    let approle_mod = module.read().unwrap();
                    let approle_module = approle_mod.as_ref().downcast_ref::<AppRoleModule>().unwrap();
                    let mut req = Request::new("auth/approle/role/role1/secret-id");
                    req.operation = Operation::Write;
                    req.client_token = token.clone();
                    let _resp = c.handle_request(&mut req);
                    req.storage = c.get_system_view().map(|arc| arc as Arc<dyn Storage>);
                    let resp = approle_module.write_role_secret_id(&mb, &mut req);
                    assert!(resp.is_ok());
                });

                let mut num = count.lock().unwrap();

                let entry = StorageEntry::new(
                    format!("accessor/invalid{}", *num).as_str(),
                    &SecretIdAccessorStorageEntry { secret_id_hmac: "samplesecretidhmac".to_string() },
                )
                .unwrap();

                assert!(req.storage_put(&entry).is_ok());

                *num += 1;

                thread::sleep(Duration::from_micros(10));
            }

            for task in &mut req.tasks {
                task.await.unwrap();
            }

            actix_rt::System::current().stop();
        });

        let _ = rt.run().unwrap();

        // Wait for tidy to finish
        while approle_module.tidy_secret_id_cas_guard.load(Ordering::SeqCst) != 0 {
            thread::sleep(Duration::from_micros(100));
        }

        // Run tidy again
        req.tasks.clear();

        let rt =
            System::with_tokio_rt(|| Builder::new_multi_thread().worker_threads(128).enable_all().build().unwrap());
        rt.block_on(async {
            req.operation = Operation::Write;
            req.path = "tidy/secret-id".to_string();
            let resp = mock_backend.handle_request(&mut req);
            assert!(resp.is_ok());

            for task in &mut req.tasks {
                task.await.unwrap();
            }

            actix_rt::System::current().stop();
        });

        let _ = rt.run().unwrap();

        let num = count.lock().unwrap();

        let accessor = req.storage_list("accessor/");
        assert!(accessor.is_ok());
        let accessor = accessor.unwrap();
        assert_eq!(accessor.len(), *num);

        let role_hmacs = req.storage_list(SECRET_ID_PREFIX);
        assert!(role_hmacs.is_ok());
        let role_hmacs = role_hmacs.unwrap();
        assert_eq!(role_hmacs.len(), 1);

        let secret_ids = req.storage_list(format!("{}{}", SECRET_ID_PREFIX, role_hmacs[0]).as_str());
        assert!(secret_ids.is_ok());
        let secret_ids = secret_ids.unwrap();
        assert_eq!(secret_ids.len(), *num);
    }
}
