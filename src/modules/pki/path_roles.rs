use std::{
    time::{Duration},
};
use humantime::parse_duration;
use serde::{Serialize, Deserialize};
use crate::{
    utils::{serialize_duration, deserialize_duration},
    logical::{
        Backend, Request, Response,
    },
    storage::StorageEntry,
    errors::RvError,
};
use super::{
    PkiBackendInner,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_ttl: Duration,
    pub key_type: String,
    pub key_bits: u32,
    pub signature_bits: u32,
    pub allow_localhost: bool,
    pub allow_bare_domains: bool,
    pub allow_subdomains: bool,
    pub allow_any_name: bool,
    pub allow_ip_sans: bool,
    pub server_flag: bool,
    pub client_flag: bool,
    pub use_csr_sans: bool,
    pub use_csr_common_name: bool,
    pub country: String,
    pub province: String,
    pub locality: String,
    pub organization: String,
    pub ou: String,
    pub no_store: bool,
    pub generate_lease: bool,
    pub not_after: String,
}

impl PkiBackendInner {
    pub fn get_role(&self, req: &mut Request, name: &str) -> Result<Option<RoleEntry>, RvError> {
        let key = format!("role/{}", name);
        let storage_entry = req.storage_get(&key)?;
        if storage_entry.is_none() {
            return Ok(None);
        }

        let entry = storage_entry.unwrap();
        let role_entry: RoleEntry = serde_json::from_slice(entry.value.as_slice())?;
        Ok(Some(role_entry))
    }

    pub fn read_path_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name_vale = req.get_data("name")?;
        let name = name_vale.as_str().unwrap();
        let role_entry = self.get_role(req, name)?;
        let data = serde_json::to_value(&role_entry)?;
        Ok(Some(Response::data_response(Some(data.as_object().unwrap().clone()))))
    }

    pub fn create_path_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name_vale = req.get_data("name")?;
        let name = name_vale.as_str().unwrap();
        let ttl_vale = req.get_data("ttl")?;
        let ttl = {
            let ttl_str = ttl_vale.as_str().unwrap();
            parse_duration(ttl_str)?
        };
        let max_ttl_vale = req.get_data("max_ttl")?;
        let max_ttl = {
            let max_ttl_str = max_ttl_vale.as_str().unwrap();
            parse_duration(max_ttl_str)?
        };
        let key_type_vale = req.get_data("key_type")?;
        let key_type = key_type_vale.as_str().unwrap();
        let key_bits_vale = req.get_data("key_bits")?;
        let mut key_bits = key_bits_vale.as_u64().unwrap();
        match key_type {
            "rsa" => {
                if key_bits == 0 {
                    key_bits = 2048;
                }

                if key_bits != 2048 && key_bits != 3072 && key_bits != 4096 {
                    return Err(RvError::ErrPkiKeyBitsInvalid);
                }
            },
            "ec" => {
                if key_bits == 0 {
                    key_bits = 256;
                }

                if key_bits != 224 && key_bits != 256 && key_bits != 384 && key_bits != 512 {
                    return Err(RvError::ErrPkiKeyBitsInvalid);
                }
            }
            _ => {
                return Err(RvError::ErrPkiKeyTypeInvalid);
            }
        }

        let signature_bits_vale = req.get_data("signature_bits")?;
        let signature_bits = signature_bits_vale.as_u64().unwrap();
        let allow_localhost_vale = req.get_data("allow_localhost")?;
        let allow_localhost = allow_localhost_vale.as_bool().unwrap();
        let allow_bare_domain_vale = req.get_data("allow_bare_domains")?;
        let allow_bare_domains = allow_bare_domain_vale.as_bool().unwrap();
        let allow_subdomains_vale = req.get_data("allow_subdomains")?;
        let allow_subdomains = allow_subdomains_vale.as_bool().unwrap();
        let allow_any_name_vale = req.get_data("allow_any_name")?;
        let allow_any_name = allow_any_name_vale.as_bool().unwrap();
        let allow_ip_sans_vale = req.get_data("allow_ip_sans")?;
        let allow_ip_sans = allow_ip_sans_vale.as_bool().unwrap();
        let server_flag_vale = req.get_data("server_flag")?;
        let server_flag = server_flag_vale.as_bool().unwrap();
        let client_flag_vale = req.get_data("client_flag")?;
        let client_flag = client_flag_vale.as_bool().unwrap();
        let use_csr_sans_vale = req.get_data("use_csr_sans")?;
        let use_csr_sans = use_csr_sans_vale.as_bool().unwrap();
        let use_csr_common_name_vale = req.get_data("use_csr_common_name")?;
        let use_csr_common_name = use_csr_common_name_vale.as_bool().unwrap();
        let country_vale = req.get_data("country")?;
        let country = country_vale.as_str().unwrap().to_string();
        let province_vale = req.get_data("province")?;
        let province = province_vale.as_str().unwrap().to_string();
        let locality_vale = req.get_data("locality")?;
        let locality = locality_vale.as_str().unwrap().to_string();
        let organization_vale = req.get_data("organization")?;
        let organization = organization_vale.as_str().unwrap().to_string();
        let ou_vale = req.get_data("ou")?;
        let ou = ou_vale.as_str().unwrap().to_string();
        let no_store_vale = req.get_data("no_store")?;
        let no_store = no_store_vale.as_bool().unwrap();
        let generate_lease_vale = req.get_data("generate_lease")?;
        let generate_lease = generate_lease_vale.as_bool().unwrap();
        let not_after_vale = req.get_data("not_after")?;
        let not_after = not_after_vale.as_str().unwrap().to_string();

        let role_entry = RoleEntry {
            ttl: ttl,
            max_ttl: max_ttl,
            key_type: key_type.to_string(),
            key_bits: key_bits as u32,
            signature_bits: signature_bits as u32,
            allow_localhost: allow_localhost,
            allow_bare_domains: allow_bare_domains,
            allow_subdomains: allow_subdomains,
            allow_any_name: allow_any_name,
            allow_ip_sans: allow_ip_sans,
            server_flag: server_flag,
            client_flag: client_flag,
            use_csr_sans: use_csr_sans,
            use_csr_common_name: use_csr_common_name,
            country: country,
            province: province,
            locality: locality,
            organization: organization,
            ou: ou,
            no_store: no_store,
            generate_lease: generate_lease,
            not_after: not_after,
        };

        let entry = StorageEntry::new(format!("role/{}", name).as_str(), &role_entry)?;

        req.storage_put(&entry)?;

        Ok(None)
    }

    pub fn delete_path_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let name_vale = req.get_data("name")?;
        let name = name_vale.as_str().unwrap();
        if name == "" {
            return Err(RvError::ErrRequestNoDataField);
        }

        req.storage_delete(format!("role/{}", name).as_str())?;
        Ok(None)
    }
}
