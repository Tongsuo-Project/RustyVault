use std::{
    sync::Arc,
    collections::HashMap,
    time::Duration,
};

use humantime::parse_duration;
use serde::{Deserialize, Serialize};

use super::{PkiBackend, PkiBackendInner};
use crate::{
    errors::RvError,
    logical::{
        Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response,
    },
    storage::StorageEntry,
    utils::{deserialize_duration, serialize_duration},
    new_path, new_path_internal, new_fields, new_fields_internal,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleEntry {
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub not_before_duration: Duration,
    pub key_type: String,
    pub key_bits: u32,
    pub signature_bits: u32,
    pub use_pss: bool,
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
    pub street_address: String,
    pub postal_code: String,
    pub no_store: bool,
    pub generate_lease: bool,
    pub not_after: String,
}

impl Default for RoleEntry {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(0),
            max_ttl: Duration::from_secs(0),
            not_before_duration: Duration::from_secs(0),
            key_type: "rsa".to_string(),
            key_bits: 2048,
            signature_bits: 256,
            use_pss: false,
            allow_localhost: true,
            allow_bare_domains: true,
            allow_subdomains: true,
            allow_any_name: true,
            allow_ip_sans: true,
            server_flag: false,
            client_flag: false,
            use_csr_sans: true,
            use_csr_common_name: true,
            country: "".to_string(),
            province: "".to_string(),
            locality: "".to_string(),
            organization: "".to_string(),
            ou: "".to_string(),
            street_address: "".to_string(),
            postal_code: "".to_string(),
            no_store: true,
            generate_lease: false,
            not_after: "".to_string(),
        }
    }
}

impl PkiBackend {
    pub fn roles_path(&self) -> Path {
        let pki_backend_ref1 = Arc::clone(&self.inner);
        let pki_backend_ref2 = Arc::clone(&self.inner);
        let pki_backend_ref3 = Arc::clone(&self.inner);

        let path = new_path!({
            pattern: r"roles/(?P<name>\w[\w-]+\w)",
            fields: {
                "name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: r#"Name of the role."#
                },
                "ttl": {
                    field_type: FieldType::Str,
                    description: r#"
The lease duration (validity period of the certificate) if no specific lease
duration is requested. The lease duration controls the expiration of certificates
issued by this backend. defaults to the system default value or the value of
max_ttl, whichever is shorter."#
                },
                "max_ttl": {
                    field_type: FieldType::Str,
                    required: true,
                    description: r#"
The maximum allowed lease duration. If not set, defaults to the system maximum lease TTL."#
                },
                "use_pss": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
Whether or not to use PSS signatures when using a RSA key-type issuer. Defaults to false."#
                },
                "allow_localhost": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
Whether to allow "localhost" and "localdomain" as a valid common name in a request,
independent of allowed_domains value."#
                },
                "allowed_domains": {
                    field_type: FieldType::Str,
                    description: r#"
Specifies the domains this role is allowed to issue certificates for.
This is used with the allow_bare_domains, allow_subdomains, and allow_glob_domains
to determine matches for the common name, DNS-typed SAN entries, and Email-typed
SAN entries of certificates. See the documentation for more information.
This parameter accepts a comma-separated string or list of domains."#
                },
                "allow_bare_domains": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
If set, clients can request certificates for the base domains themselves,
e.g. "example.com" of domains listed in allowed_domains. This is a separate
option as in some cases this can be considered a security threat.
See the documentation for more information."#
                },
                "allow_subdomains": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
If set, clients can request certificates for subdomains of domains listed in
allowed_domains, including wildcard subdomains. See the documentation for more information."#
                },
                "allow_any_name": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
If set, clients can request certificates for any domain, regardless of allowed_domains restrictions.
See the documentation for more information."#
                },
                "allow_ip_sans": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
If set, IP Subject Alternative Names are allowed. Any valid IP is accepted and No authorization checking is performed."#
                },
                "server_flag": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
If set, certificates are flagged for server auth use. defaults to true. See also RFC 5280 Section 4.2.1.12."#
                },
                "client_flag": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
If set, certificates are flagged for client auth use. defaults to true. See also RFC 5280 Section 4.2.1.12."#
                },
                "code_signing_flag": {
                    field_type: FieldType::Bool,
                    description: r#"
If set, certificates are flagged for code signing use. defaults to false. See also RFC 5280 Section 4.2.1.12."#
                },
                "key_type": {
                    field_type: FieldType::Str,
                    default: "rsa",
                    description: r#"
The type of key to use; defaults to RSA. "rsa" "ec", "ed25519" and "any" are the only valid values."#
                },
                "key_bits": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: r#"
The number of bits to use. Allowed values are 0 (universal default); with rsa
key_type: 2048 (default), 3072, or 4096; with ec key_type: 224, 256 (default),
384, or 521; ignored with ed25519."#
                },
                "signature_bits": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: r#"
The number of bits to use in the signature algorithm; accepts 256 for SHA-2-256,
384 for SHA-2-384, and 512 for SHA-2-512. defaults to 0 to automatically detect
based on key length (SHA-2-256 for RSA keys, and matching the curve size for NIST P-Curves)."#
                },
                "not_before_duration": {
                    field_type: FieldType::Int,
                    default: 30,
                    description: r#"
The duration before now which the certificate needs to be backdated by."#
                },
                "not_after": {
                    field_type: FieldType::Str,
                    default: "",
                    description: r#"
Set the not after field of the certificate with specified date value.
The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ."#
                },
                "ou": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, OU (OrganizationalUnit) will be set to this value in certificates issued by this role."#
                },
                "organization": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, O (Organization) will be set to this value in certificates issued by this role."#
                },
                "country": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, Country will be set to this value in certificates issued by this role."#
                },
                "locality": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, Locality will be set to this value in certificates issued by this role."#
                },
                "province": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, Province will be set to this value in certificates issued by this role."#
                },
                "street_address": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, Street Address will be set to this value."#
                },
                "postal_code": {
                    required: false,
                    field_type: FieldType::Str,
                    description: r#"
If set, Postal Code will be set to this value."#
                },
                "use_csr_common_name": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
If set, when used with a signing profile, the common name in the CSR will be used. This
does *not* include any requested Subject Alternative Names; use use_csr_sans for that. defaults to true."#
                },
                "use_csr_sans": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: r#"
If set, when used with a signing profile, the SANs in the CSR will be used. This does *not*
include the Common Name (cn); use use_csr_common_name for that. defaults to true."#
                },
                "generate_lease": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
If set, certificates issued/signed against this role will have RustyVault leases
attached to them. Defaults to "false". Certificates can be added to the CRL by
"vault revoke <lease_id>" when certificates are associated with leases.  It can
also be done using the "pki/revoke" endpoint. However, when lease generation is
disabled, invoking "pki/revoke" would be the only way to add the certificates
to the CRL.  When large number of certificates are generated with long
lifetimes, it is recommended that lease generation be disabled, as large amount of
leases adversely affect the startup time of RustyVault."#
                },
                "no_store": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: r#"
If set, certificates issued/signed against this role will not be stored in the
storage backend. This can improve performance when issuing large numbers of
certificates. However, certificates issued in this way cannot be enumerated
or revoked, so this option is recommended only for certificates that are
non-sensitive, or extremely short-lived. This option implies a value of "false"
for "generate_lease"."#
                }
            },
            operations: [
                {op: Operation::Read, handler: pki_backend_ref1.read_path_role},
                {op: Operation::Write, handler: pki_backend_ref2.create_path_role},
                {op: Operation::Delete, handler: pki_backend_ref3.delete_path_role}
            ],
            help: "This path lets you manage the roles that can be created with this backend."
        });

        path
    }
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
            }
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
        let street_address_vale = req.get_data("street_address")?;
        let street_address = street_address_vale.as_str().unwrap().to_string();
        let postal_code_vale = req.get_data("postal_code")?;
        let postal_code = postal_code_vale.as_str().unwrap().to_string();
        let no_store_vale = req.get_data("no_store")?;
        let no_store = no_store_vale.as_bool().unwrap();
        let generate_lease_vale = req.get_data("generate_lease")?;
        let generate_lease = generate_lease_vale.as_bool().unwrap();
        let not_after_vale = req.get_data("not_after")?;
        let not_after = not_after_vale.as_str().unwrap().to_string();
        let not_before_duration_vale = req.get_data("not_before_duration")?;
        let not_before_duration = Duration::from_secs(not_before_duration_vale.as_u64().unwrap());

        let role_entry = RoleEntry {
            ttl,
            max_ttl,
            key_type: key_type.to_string(),
            key_bits: key_bits as u32,
            signature_bits: signature_bits as u32,
            allow_localhost,
            allow_bare_domains,
            allow_subdomains,
            allow_any_name,
            allow_ip_sans,
            server_flag,
            client_flag,
            use_csr_sans,
            use_csr_common_name,
            country,
            province,
            locality,
            organization,
            ou,
            no_store,
            generate_lease,
            not_after,
            not_before_duration,
            street_address,
            postal_code,
            ..Default::default()
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
