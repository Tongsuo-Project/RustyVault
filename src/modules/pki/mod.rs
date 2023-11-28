use std::{
    collections::HashMap,
    ops::Deref,
    sync::{atomic::AtomicU64, Arc, RwLock},
    time::Duration,
};

use crate::{
    core::Core,
    errors::RvError,
    logical::{
        secret::Secret, Backend, Field, FieldType, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    modules::Module,
    new_logical_backend, new_logical_backend_internal, new_path, new_path_internal, new_secret, new_secret_internal,
};

pub mod path_config_ca;
pub mod path_config_crl;
pub mod path_fetch;
pub mod path_issue;
pub mod path_keys;
pub mod path_revoke;
pub mod path_roles;

static PKI_BACKEND_HELP: &str = r#"
The PKI backend dynamically generates X509 server and client certificates.

After mounting this backend, configure the CA using the "pem_bundle" endpoint within
the "config/" path.
"#;
const _DEFAULT_LEASE_TTL: Duration = Duration::from_secs(3600 as u64);

pub struct PkiModule {
    pub name: String,
    pub backend: Arc<PkiBackend>,
}

pub struct PkiBackendInner {
    pub core: Arc<RwLock<Core>>,
    pub cert_count: AtomicU64,
    pub revoked_cert_count: AtomicU64,
}

pub struct PkiBackend {
    pub inner: Arc<PkiBackendInner>,
}

impl Deref for PkiBackend {
    type Target = PkiBackendInner;

    fn deref(&self) -> &PkiBackendInner {
        &self.inner
    }
}

impl PkiBackend {
    pub fn new(core: Arc<RwLock<Core>>) -> Self {
        Self {
            inner: Arc::new(PkiBackendInner {
                core,
                cert_count: AtomicU64::new(0),
                revoked_cert_count: AtomicU64::new(0),
            }),
        }
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let pki_backend_ref1 = Arc::clone(&self.inner);
        let pki_backend_ref2 = Arc::clone(&self.inner);
        let pki_backend_ref3 = Arc::clone(&self.inner);
        let pki_backend_ref4 = Arc::clone(&self.inner);
        let pki_backend_ref5 = Arc::clone(&self.inner);
        let pki_backend_ref6 = Arc::clone(&self.inner);
        let pki_backend_ref7 = Arc::clone(&self.inner);
        let pki_backend_ref8 = Arc::clone(&self.inner);
        let pki_backend_ref9 = Arc::clone(&self.inner);
        let pki_backend_ref10 = Arc::clone(&self.inner);
        let pki_backend_ref11 = Arc::clone(&self.inner);
        let pki_backend_ref12 = Arc::clone(&self.inner);
        let pki_backend_ref13 = Arc::clone(&self.inner);
        let pki_backend_ref14 = Arc::clone(&self.inner);
        let pki_backend_ref15 = Arc::clone(&self.inner);
        let pki_backend_ref16 = Arc::clone(&self.inner);
        let pki_backend_ref17 = Arc::clone(&self.inner);
        let pki_backend_ref18 = Arc::clone(&self.inner);
        let pki_backend_ref19 = Arc::clone(&self.inner);
        let pki_backend_ref20 = Arc::clone(&self.inner);
        let pki_backend_ref21 = Arc::clone(&self.inner);

        let backend = new_logical_backend!({
            root_paths: ["config/*", "revoke/*", "crl/rotate"],
            unauth_paths: ["cert/*", "ca/pem", "ca", "crl", "crl/pem"],
            paths: [
                {
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
                },
                {
                    pattern: "config/ca",
                    fields: {
                        "pem_bundle": {
                            field_type: FieldType::Str,
                            description: "PEM-format, concatenated unencrypted secret key and certificate"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref4.write_path_ca}
                    ],
                    help: r#"
This configures the CA information used for credentials
generated by this backend. This must be a PEM-format, concatenated
unencrypted secret key and certificate.

For security reasons, you can only view the certificate when reading this endpoint
                        "#
                },
                {
                    pattern: "config/crl",
                    fields: {
                        "expiry": {
                            field_type: FieldType::Str,
                            default: "72h",
                            description: "The amount of time the generated CRL should be valid; defaults to 72 hours"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref5.read_path_crl},
                        {op: Operation::Write, handler: pki_backend_ref6.write_path_crl}
                    ],
                    help: r#"
This endpoint allows configuration of the CRL lifetime.
                        "#
                },
                {
                    pattern: "ca(/pem)?",
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref7.read_path_fetch_ca}
                    ],
                    help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                        "#
                },
                {
                    pattern: "crl(/pem)?",
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref8.read_path_fetch_crl}
                    ],
                    help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                        "#
                },
                {
                    pattern: r"cert/(?P<serial>[0-9A-Fa-f-:]+)",
                    fields: {
                        "serial": {
                            field_type: FieldType::Str,
                            default: "72h",
                            description: "Certificate serial number, in colon- or hyphen-separated octal"
                        }
                    },
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref9.read_path_fetch_cert}
                    ],
                    help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                        "#
                },
                {
                    pattern: "cert/crl",
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref10.read_path_fetch_cert_crl}
                    ],
                    help: r#"
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.
Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.
                        "#
                },
                {
                    pattern: r"issue/(?P<role>\w[\w-]+\w)",
                    fields: {
                        "role": {
                            field_type: FieldType::Str,
                            description: "The desired role with configuration for this request"
                        },
                        "common_name": {
                            field_type: FieldType::Str,
                            description: r#"
        The requested common name; if you want more than one, specify the alternative names in the alt_names map"#
                        },
                        "alt_names": {
                            required: false,
                            field_type: FieldType::Str,
                            description: r#"
        The requested Subject Alternative Names, if any, in a comma-delimited list"#
                        },
                        "ip_sans": {
                            required: false,
                            field_type: FieldType::Str,
                            description: r#"The requested IP SANs, if any, in a common-delimited list"#
                        },
                        "ttl": {
                            required: false,
                            field_type: FieldType::Str,
                            description: r#"Specifies requested Time To Live"#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref11.issue_cert}
                    ],
                    help: r#"
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.
                        "#
                },
                {
                    pattern: "revoke",
                    fields: {
                        "serial_number": {
                            field_type: FieldType::Str,
                            description: "Certificate serial number, in colon- or hyphen-separated octal"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref12.revoke_cert}
                    ],
                    help: r#"
This allows certificates to be revoked using its serial number. A root token is required.
                        "#
                },
                {
                    pattern: "crl/rotate",
                    operations: [
                        {op: Operation::Read, handler: pki_backend_ref13.read_rotate_crl}
                    ],
                    help: r#"
Force a rebuild of the CRL. This can be used to remove expired certificates from it if no certificates have been revoked. A root token is required.
                        "#
                },
                {
                    pattern: r"keys/generate/(exported|internal)",
                    fields: {
                        "key_name": {
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "key_bits": {
                            required: true,
                            field_type: FieldType::Int,
                            description: r#"
The number of bits to use. Allowed values are 0 (universal default); with rsa
key_type: 2048 (default), 3072, or 4096; with ec key_type: 224, 256 (default),
384, or 521; ignored with ed25519."#
                        },
                        "key_type": {
                            field_type: FieldType::Str,
                            default: "rsa",
                            description: r#"The type of key to use; defaults to RSA. "rsa""#
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref16.generate_key}
                    ],
                    help: r#"
This endpoint will generate a new key pair of the specified type (internal, exported)
used for sign,verify,encrypt,decrypt.
                        "#
                },
                {
                    pattern: r"keys/import",
                    fields: {
                        "key_name": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "key_type": {
                            field_type: FieldType::Str,
                            default: "rsa",
                            description: r#"The type of key to use; defaults to RSA. "rsa""#
                        },
                        "pem_bundle": {
                            field_type: FieldType::Str,
                            description: "PEM-format, unencrypted secret"
                        },
                        "hex_bundle": {
                            field_type: FieldType::Str,
                            description: "Hex-format, unencrypted secret"
                        },
                        "iv": {
                            field_type: FieldType::Str,
                            description: "IV for aes-gcm/aes-cbc"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref17.import_key}
                    ],
                    help: "Import the specified key."
                },
                {
                    pattern: r"keys/sign",
                    fields: {
                        "key_name": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "data": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "Data that needs to be signed"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref18.key_sign}
                    ],
                    help: "Data Signatures."
                },
                {
                    pattern: r"keys/verify",
                    fields: {
                        "key_name": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "data": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "Data that needs to be verified"
                        },
                        "signature": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "Signature data"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref19.key_verify}
                    ],
                    help: "Data verification."
                },
                {
                    pattern: r"keys/encrypt",
                    fields: {
                        "key_name": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "data": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "Data that needs to be encrypted"
                        },
                        "aad": {
                            required: false,
                            field_type: FieldType::Str,
                            description: "Additional Authenticated Data can be provided for aes-gcm/cbc encryption"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref20.key_encrypt}
                    ],
                    help: "Data encryption."
                },
                {
                    pattern: r"keys/decrypt",
                    fields: {
                        "key_name": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "key name"
                        },
                        "data": {
                            required: true,
                            field_type: FieldType::Str,
                            description: "Data that needs to be decrypted"
                        },
                        "aad": {
                            required: false,
                            field_type: FieldType::Str,
                            description: "Additional Authenticated Data can be provided for aes-gcm/cbc decryption"
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: pki_backend_ref21.key_decrypt}
                    ],
                    help: "Data decryption."
                }
            ],
            secrets: [{
                secret_type: "pki",
                revoke_handler: pki_backend_ref14.revoke_secret_creds,
                renew_handler: pki_backend_ref15.renew_secret_creds,
            }],
            help: PKI_BACKEND_HELP
        });

        backend
    }
}

impl PkiBackendInner {
    pub fn revoke_secret_creds(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
    pub fn renew_secret_creds(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

impl PkiModule {
    pub fn new(core: &Core) -> Self {
        Self {
            name: "pki".to_string(),
            backend: Arc::new(PkiBackend::new(Arc::clone(core.self_ref.as_ref().unwrap()))),
        }
    }
}

impl Module for PkiModule {
    fn name(&self) -> String {
        return self.name.clone();
    }

    fn setup(&mut self, core: &Core) -> Result<(), RvError> {
        let pki = Arc::clone(&self.backend);
        let pki_backend_new_func = move |_c: Arc<RwLock<Core>>| -> Result<Arc<dyn Backend>, RvError> {
            let mut pki_backend = pki.new_backend();
            pki_backend.init()?;
            Ok(Arc::new(pki_backend))
        };
        core.add_logical_backend("pki", Arc::new(pki_backend_new_func))
    }

    fn cleanup(&mut self, core: &Core) -> Result<(), RvError> {
        core.delete_logical_backend("pki")
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        default::Default,
        env, fs,
        sync::{Arc, RwLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use go_defer::defer;
    use openssl::{asn1::Asn1Time, ec::EcKey, pkey::PKey, rsa::Rsa, x509::X509};
    use serde_json::{json, Map, Value};

    use super::*;
    use crate::{
        core::{Core, SealConfig},
        logical::{Operation, Request},
        storage::{barrier_aes_gcm, physical},
    };

    const CA_CERT_PEM: &str = r#"
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290
IENBMCAXDTIwMTIxMjIwMTY1MFoYDzIxMjAxMjEzMjAxNjUwWjANMQswCQYDVQQD
DAJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJadpD0ASxxfxsvd
j9IxsogVzMSGLFziaYuE9KejU9+R479RifvwfBANO62sNWJ19X//9G5UjwWmkiOz
n1k50DkYsBBA3mJzik6wjt/c58lBIlSEgAgpvDU8ht8w3t20JP9+YqXAeugqFj/W
l9rFQtsvaWSRywjXVlp5fxuEQelNnXcJEKhsKTNExsBUZebo4/J1BWpklWzA9P0l
YW5INvDAAwcF1nzlEf0Y6Eot03IMNyg2MTE4hehxjdgCSci8GYnFirE/ojXqqpAc
ZGh7r2dqWgZUD1Dh+bT2vjrUzj8eTH3GdzI+oljt29102JIUaqj3yzRYkah8FLF9
CLNNsUcCAwEAAaNgMF4wDwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYD
VR0OBBYEFLQRM/HX4l73U54gIhBPhga/H8leMB8GA1UdIwQYMBaAFI71Ja8em2uE
PXyAmslTnE1y96NSMA0GCSqGSIb3DQEBCwUAA4IBAQDacg5HHo+yaApPb6mk/SP8
J3CjQWhRzv91kwsGLnhPgZI4HcspdJgTaznrstiiA1VRjkQ/kwzd29Sftb1kBio0
pAyblmravufRdojfTgkMnFyRSaj4FHuOQq8lnX3gwlKn5hBtEF6Qd+U79MkpMALa
cxPdyJs2tgDOpP1jweubOawqsKlxhAjwgdeX0Qp8iUj4BrY0zg4Q5im0mEKo4hij
49dQQqoWakCejH4QP2+T1urJsRGn9rXk/nkW9daNYaQDyoAPlnhr5oU+pP3+hSec
Ol83n08VZ8BizTSPkG0J66sZGC5jvsf5rX8YHURv0jNxHcG8QVEmyCwPqfDTI4fz
-----END CERTIFICATE-----"#;
    const CA_KEY_PEM: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCWnaQ9AEscX8bL
3Y/SMbKIFczEhixc4mmLhPSno1PfkeO/UYn78HwQDTutrDVidfV///RuVI8FppIj
s59ZOdA5GLAQQN5ic4pOsI7f3OfJQSJUhIAIKbw1PIbfMN7dtCT/fmKlwHroKhY/
1pfaxULbL2lkkcsI11ZaeX8bhEHpTZ13CRCobCkzRMbAVGXm6OPydQVqZJVswPT9
JWFuSDbwwAMHBdZ85RH9GOhKLdNyDDcoNjExOIXocY3YAknIvBmJxYqxP6I16qqQ
HGRoe69naloGVA9Q4fm09r461M4/Hkx9xncyPqJY7dvddNiSFGqo98s0WJGofBSx
fQizTbFHAgMBAAECggEABdXHpiFbx5aiUgWca81HGGSX0UlNcK/I3QHipJf8SN4T
D7dt/Be+BrUsibbxPoZJY5Mb+iZGgDaK1N1BoChQO9YMBCUvOGs3gYLvlhat2Csw
1Etp1mcfhoR4yS7Qg5BWGpvf4IILgPEYeZKrwWsBAxLcJ2xKjGYjT1ADr6I5F3u+
FYN+bvlXxr07GccfS+UHt04oT0dHwxQzFaJj+yqKWGo2IFtPqtr6Sgoh9a+yFYIi
8a9MigTTt+IyJ55OuC/FHRf1PofprftADFts78k43qxWtrxSrQVdlNXp1lpZOtuR
7gvB/r3a2byDYxCxYVu98tQuOfW909TdDgPmEJjcAQKBgQDHcTYi+zcGKooN3tfK
Oc6hnFXAYTNpYp074NfIYB8i10CwbvWta1FDoi3iRqlQFwg+pu12UefZsj21F+aF
v2eGP33kQ6yiXJQ3j7jam7dY+tZ6xb0dthm+X/INuHp/HbSb1qKFmSO2rmMDQg+e
Crqts9+t5Xk04ewTgpySLZjvRwKBgQDBU85Ls3s8osre5EmVBRd5qBt6ILnjtdoa
UxrrrWopRx2q3HsI41VhKFx0PGs6ia0c6+9GFR6wX/Qevj85DADbzHDA5XEZq98q
8yH4lme2Uj2gOlWqyhDeC/g4S+MsbNoIaUOZbMGg/phyAe20HvtvD7MUhZ/2rkta
U5UjFpouAQKBgQC/+vU+tQ0hTV94vJKBoiWKIX/V4HrprbhmxCdSRVyTYBpv+09X
8J7X+MwsLRKb+p/AF1UreOox/sYxhOEsy7MuYf2f9Zi+7VjrJtis7gmOiF5e7er+
J6UeQSMyG+smY4TQIcptyZy8I59Bqpx36CIMRMJClUqYIgTqPubSOzwkzwKBgENB
9LNBbc5alFmW8kJ10wTwBx8l44Xk7kvaPbNgUV6q7xdSPTuKW1nBwOhvXJ6w5xj4
u/WVw2d4+mT3qucd1e6h4Vg6em6D7M/0Zg0lxk8XrXjg0ozoX5XgdCqhvBboh7IF
bQ8jVvm7mS2QnjHb1X196L9q/YvEd1KlYW0jn+ABAoGBAKwArjjmr3zRhJurujA5
x/+V28hUf8m8P2NxP5ALaDZagdaMfzjGZo3O3wDv33Cds0P5GMGQYnRXDxcZN/2L
/453f0uUObRwFepuv9HzuvPgkTRGpcLFiIHCThiKdyBgPKoq39qjbAyWQcfmW8+S
2k24wuH7oUtLlvf05p4cqfEx
-----END PRIVATE KEY-----"#;

    fn test_read_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Read;
        req.client_token = token.to_string();
        let resp = core.handle_request(&mut req);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_write_api(
        core: &Core,
        token: &str,
        path: &str,
        is_ok: bool,
        data: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = data;

        let resp = core.handle_request(&mut req);
        println!("path: {}, resp: {:?}", path, resp);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    /*
    fn test_delete_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Delete;
        req.client_token = token.to_string();
        let resp = core.handle_request(&mut req);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }

    fn test_list_api(core: &Core, token: &str, path: &str, is_ok: bool) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::List;
        req.client_token = token.to_string();
        let resp = core.handle_request(&mut req);
        assert_eq!(resp.is_ok(), is_ok);
        resp
    }
    */

    fn test_pki_config_ca(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();

        // mount pki backend to path: pki/
        let mount_data = json!({
            "type": "pki",
        })
        .as_object()
        .unwrap()
        .clone();

        let resp = test_write_api(&core, token, "sys/mounts/pki/", true, Some(mount_data));
        assert!(resp.is_ok());

        let ca_pem_bundle = format!("{}{}", CA_CERT_PEM, CA_KEY_PEM);

        let ca_data = json!({
            "pem_bundle": ca_pem_bundle,
        })
        .as_object()
        .unwrap()
        .clone();

        // config ca
        let resp = test_write_api(&core, token, "pki/config/ca", true, Some(ca_data));
        assert!(resp.is_ok());
        let resp_ca = test_read_api(&core, token, "pki/ca", true);
        let resp_ca_pem = test_read_api(&core, token, "pki/ca/pem", true);
        let resp_ca_cert_data = resp_ca.unwrap().unwrap().data.unwrap();
        let resp_ca_pem_cert_data = resp_ca_pem.unwrap().unwrap().data.unwrap();
        assert!(resp_ca_cert_data.get("private_key").is_none());
        assert!(resp_ca_pem_cert_data.get("private_key").is_none());
        assert_eq!(
            resp_ca_cert_data["certificate"].as_str().unwrap(),
            resp_ca_pem_cert_data["certificate"].as_str().unwrap()
        );
        assert_eq!(
            resp_ca_cert_data["serial_number"].as_str().unwrap(),
            resp_ca_pem_cert_data["serial_number"].as_str().unwrap()
        );
        assert_eq!(resp_ca_cert_data["certificate"].as_str().unwrap().trim(), CA_CERT_PEM.trim());
    }

    fn test_pki_config_role(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();

        let role_data = json!({
            "ttl": "60d",
            "max_ttl": "365d",
            "key_type": "rsa",
            "key_bits": 4096,
            "country": "CN",
            "province": "ZJ",
            "locality": "HZ",
            "organization": "ANT-Group",
            "ou": "Big-Security",
            "no_store": false,
        })
        .as_object()
        .unwrap()
        .clone();

        // config role
        assert!(test_write_api(&core, token, "pki/roles/test", true, Some(role_data)).is_ok());
        let resp = test_read_api(&core, token, "pki/roles/test", true);
        assert!(resp.as_ref().unwrap().is_some());
        let resp = resp.unwrap();
        assert!(resp.is_some());
        let data = resp.unwrap().data;
        assert!(data.is_some());
        let role_data = data.unwrap();
        assert_eq!(role_data["ttl"].as_u64().unwrap(), 60 * 24 * 60 * 60);
        assert_eq!(role_data["max_ttl"].as_u64().unwrap(), 365 * 24 * 60 * 60);
        assert_eq!(role_data["key_type"].as_str().unwrap(), "rsa");
        assert_eq!(role_data["key_bits"].as_u64().unwrap(), 4096);
        assert_eq!(role_data["country"].as_str().unwrap(), "CN");
        assert_eq!(role_data["province"].as_str().unwrap(), "ZJ");
        assert_eq!(role_data["locality"].as_str().unwrap(), "HZ");
        assert_eq!(role_data["organization"].as_str().unwrap(), "ANT-Group");
        assert_eq!(role_data["ou"].as_str().unwrap(), "Big-Security");
        assert_eq!(role_data["no_store"].as_bool().unwrap(), false);
    }

    fn test_pki_issue_cert(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();

        let dns_sans = vec!["test.com", "a.test.com", "b.test.com"];
        let issue_data = json!({
            "ttl": "10d",
            "common_name": "test.com",
            "alt_names": "a.test.com,b.test.com",
        })
        .as_object()
        .unwrap()
        .clone();

        // issue cert
        let resp = test_write_api(&core, token, "pki/issue/test", true, Some(issue_data));
        assert!(resp.is_ok());
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let data = resp_body.unwrap().data;
        assert!(data.is_some());
        let cert_data = data.unwrap();
        let cert = X509::from_pem(cert_data["certificate"].as_str().unwrap().as_bytes()).unwrap();
        let alt_names = cert.subject_alt_names();
        assert!(alt_names.is_some());
        let alt_names = alt_names.unwrap();
        assert_eq!(alt_names.len(), dns_sans.len());
        for alt_name in alt_names {
            assert!(dns_sans.contains(&alt_name.dnsname().unwrap()));
        }
        assert_eq!(cert_data["private_key_type"].as_str().unwrap(), "rsa");
        let priv_key = PKey::private_key_from_pem(cert_data["private_key"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(priv_key.bits(), 4096);
        assert!(priv_key.public_eq(&cert.public_key().unwrap()));
        let serial_number = cert.serial_number().to_bn().unwrap();
        let serial_number_hex = serial_number.to_hex_str().unwrap();
        assert_eq!(
            cert_data["serial_number"].as_str().unwrap().replace(":", "").to_lowercase().as_str(),
            serial_number_hex.to_lowercase().as_str()
        );
        let expiration_time = Asn1Time::from_unix(cert_data["expiration"].as_i64().unwrap()).unwrap();
        let ttl_compare = cert.not_after().compare(&expiration_time);
        assert!(ttl_compare.is_ok());
        assert_eq!(ttl_compare.unwrap(), std::cmp::Ordering::Equal);
        let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expiration_ttl = cert_data["expiration"].as_u64().unwrap();
        let ttl = expiration_ttl - now_timestamp;
        let expect_ttl = 10 * 24 * 60 * 60;
        assert!(ttl <= expect_ttl);
        assert!((ttl + 10) > expect_ttl);

        //test fetch cert
        let serial_number_hex = cert_data["serial_number"].as_str().unwrap();
        let resp_lowercase = test_read_api(
            &core,
            token,
            format!("pki/cert/{}", serial_number_hex.to_lowercase().as_str()).as_str(),
            true,
        );
        let resp_uppercase = test_read_api(
            &core,
            token,
            format!("pki/cert/{}", serial_number_hex.to_uppercase().as_str()).as_str(),
            true,
        );
        let resp_lowercase_cert_data = resp_lowercase.unwrap().unwrap().data.unwrap();
        let resp_uppercase_cert_data = resp_uppercase.unwrap().unwrap().data.unwrap();
        assert!(resp_lowercase_cert_data.get("private_key").is_none());
        assert!(resp_uppercase_cert_data.get("private_key").is_none());
        assert_eq!(
            resp_lowercase_cert_data["certificate"].as_str().unwrap(),
            resp_uppercase_cert_data["certificate"].as_str().unwrap()
        );
        assert_eq!(
            cert_data["certificate"].as_str().unwrap(),
            resp_uppercase_cert_data["certificate"].as_str().unwrap()
        );
        assert_eq!(
            cert_data["serial_number"].as_str().unwrap(),
            resp_lowercase_cert_data["serial_number"].as_str().unwrap()
        );
    }

    fn test_pki_generate_key_case(
        core: &Core,
        token: &str,
        key_name: &str,
        key_type: &str,
        key_bits: u32,
        exported: bool,
        is_ok: bool,
    ) {
        let req_data = json!({
            "key_name": key_name.to_string(),
            "key_type": key_type.to_string(),
            "key_bits": key_bits,
        })
        .as_object()
        .unwrap()
        .clone();
        println!("generate req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(
            core,
            token,
            format!("pki/keys/generate/{}", if exported { "exported" } else { "internal" }).as_str(),
            is_ok,
            Some(req_data),
        );
        if !is_ok {
            return;
        }
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let data = resp_body.unwrap().data;
        assert!(data.is_some());
        let key_data = data.unwrap();
        println!("generate key result: {:?}", key_data);
        assert_eq!(key_data["key_name"].as_str().unwrap(), key_name);
        assert_eq!(key_data["key_type"].as_str().unwrap(), key_type);
        assert_eq!(key_data["key_bits"].as_u64().unwrap(), key_bits as u64);
        if exported {
            assert!(key_data["private_key"].as_str().is_some());
            let private_key_pem = key_data["private_key"].as_str().unwrap();
            match key_type {
                "rsa" => {
                    let rsa_key = Rsa::private_key_from_pem(private_key_pem.as_bytes());
                    assert!(rsa_key.is_ok());
                    assert_eq!(rsa_key.unwrap().size() * 8, key_bits);
                }
                "ec" => {
                    let ec_key = EcKey::private_key_from_pem(private_key_pem.as_bytes());
                    assert!(ec_key.is_ok());
                    assert_eq!(ec_key.unwrap().group().degree(), key_bits);
                }
                "aes-gcm" | "aes-cbc" | "aes-ecb" => {
                    let aes_key = hex::decode(private_key_pem.as_bytes());
                    assert!(aes_key.is_ok());
                    assert_eq!(aes_key.unwrap().len() as u32 * 8, key_bits);
                }
                _ => {}
            }
        } else {
            assert!(key_data.get("private_key").is_none());
        }
    }

    fn test_pki_import_key_case(
        core: &Core,
        token: &str,
        key_name: &str,
        key_type: &str,
        key_bits: u32,
        iv: &str,
        data: &str,
        is_ok: bool,
    ) {
        let mut req_data = json!({
            "key_name": key_name.to_string(),
            "key_type": key_type.to_string(),
        })
        .as_object()
        .unwrap()
        .clone();

        match key_type {
            "rsa" | "ec" => {
                req_data.insert("pem_bundle".to_string(), Value::String(data.to_string()));
            }
            "aes-gcm" | "aes-cbc" | "aes-ecb" => {
                req_data.insert("hex_bundle".to_string(), Value::String(data.to_string()));
                req_data.insert("iv".to_string(), Value::String(iv.to_string()));
            }
            _ => {}
        }

        println!("import req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/import", is_ok, Some(req_data));
        if !is_ok {
            return;
        }
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let data = resp_body.unwrap().data;
        assert!(data.is_some());
        let key_data = data.unwrap();
        println!("import key result: {:?}", key_data);
        assert_eq!(key_data["key_name"].as_str().unwrap(), key_name);
        assert_eq!(key_data["key_type"].as_str().unwrap(), key_type);
        assert_eq!(key_data["key_bits"].as_u64().unwrap(), key_bits as u64);
    }

    fn test_pki_sign_verify(core: &Core, token: &str, key_name: &str, data: &[u8], is_ok: bool) {
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": hex::encode(data),
        })
        .as_object()
        .unwrap()
        .clone();
        println!("sign req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/sign", is_ok, Some(req_data));
        if !is_ok {
            return;
        }
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        println!("sign resp_data: {:?}", resp_data);

        let signature = resp_data["result"].as_str().unwrap();

        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": hex::encode(data),
            "signature": signature,
        })
        .as_object()
        .unwrap()
        .clone();
        println!("verify req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/verify", is_ok, Some(req_data));
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        println!("verify resp_data: {:?}", resp_data);
        assert_eq!(resp_data["result"].as_bool().unwrap(), true);

        //test bad data
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": hex::encode("bad data".as_bytes()),
            "signature": signature,
        })
        .as_object()
        .unwrap()
        .clone();
        println!("verify bad req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/verify", true, Some(req_data));
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        assert_eq!(resp_data["result"].as_bool().unwrap(), false);

        //test bad signature
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": hex::encode(data),
            "signature": signature[2..],
        })
        .as_object()
        .unwrap()
        .clone();
        println!("verify bad signatue req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/verify", true, Some(req_data));
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        assert_eq!(resp_data["result"].as_bool().unwrap(), false);

        //test bad signature len
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": hex::encode(data),
            "signature": signature[1..],
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(test_write_api(core, token, "pki/keys/verify", false, Some(req_data)).is_err());
    }

    fn test_pki_encrypt_decrypt(core: &Core, token: &str, key_name: &str, data: &[u8], is_ok: bool) {
        let origin_data = hex::encode(data);
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": origin_data.clone(),
        })
        .as_object()
        .unwrap()
        .clone();
        println!("encrypt req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/encrypt", is_ok, Some(req_data));
        if !is_ok {
            return;
        }
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        println!("encrypt resp_data: {:?}", resp_data);

        let encrypted_data = resp_data["result"].as_str().unwrap();

        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": encrypted_data,
        })
        .as_object()
        .unwrap()
        .clone();
        println!("decrypt req_data: {:?}, is_ok: {}", req_data, is_ok);
        let resp = test_write_api(core, token, "pki/keys/decrypt", is_ok, Some(req_data));
        let resp_body = resp.unwrap();
        assert!(resp_body.is_some());
        let resp_raw_data = resp_body.unwrap().data;
        assert!(resp_raw_data.is_some());
        let resp_data = resp_raw_data.unwrap();
        println!("decrypt resp_data: {:?}", resp_data);
        assert_eq!(resp_data["result"].as_str().unwrap(), origin_data.as_str());

        //test bad data
        let req_data = json!({
            "key_name": key_name.to_string(),
            "data": encrypted_data[1..],
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(test_write_api(core, token, "pki/keys/decrypt", false, Some(req_data)).is_err());
    }

    fn test_pki_generate_key(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();

        //test generate rsa key
        test_pki_generate_key_case(&core, token, "rsa-2048", "rsa", 2048, true, true);
        test_pki_generate_key_case(&core, token, "rsa-3072", "rsa", 3072, true, true);
        test_pki_generate_key_case(&core, token, "rsa-4096", "rsa", 4096, true, true);
        test_pki_generate_key_case(&core, token, "rsa-2048-internal", "rsa", 2048, false, true);
        test_pki_generate_key_case(&core, token, "rsa-3072-internal", "rsa", 3072, false, true);
        test_pki_generate_key_case(&core, token, "rsa-4096-internal", "rsa", 4096, false, true);
        test_pki_generate_key_case(&core, token, "rsa-2048", "rsa", 2048, true, false);
        test_pki_generate_key_case(&core, token, "rsa-2048-bad-type", "rsaa", 2048, true, false);
        test_pki_generate_key_case(&core, token, "rsa-2048-bad-bits", "rsa", 2049, true, false);

        //test rsa sign and verify
        test_pki_sign_verify(&core, token, "rsa-2048", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "rsa-3072", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "rsa-4096", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "rsa-4096-bad-key-name", "rusty_vault test".as_bytes(), false);

        //test generate ec key
        test_pki_generate_key_case(&core, token, "ec-224", "ec", 224, true, true);
        test_pki_generate_key_case(&core, token, "ec-256", "ec", 256, true, true);
        test_pki_generate_key_case(&core, token, "ec-384", "ec", 384, true, true);
        test_pki_generate_key_case(&core, token, "ec-521", "ec", 521, true, true);
        test_pki_generate_key_case(&core, token, "ec-224-internal", "ec", 224, false, true);
        test_pki_generate_key_case(&core, token, "ec-256-internal", "ec", 256, false, true);
        test_pki_generate_key_case(&core, token, "ec-384-internal", "ec", 384, false, true);
        test_pki_generate_key_case(&core, token, "ec-521-internal", "ec", 521, false, true);
        test_pki_generate_key_case(&core, token, "ec-224", "ec", 224, true, false);
        test_pki_generate_key_case(&core, token, "ec-224-bad_type", "ecc", 224, true, false);
        test_pki_generate_key_case(&core, token, "ec-224-bad_bits", "ec", 250, true, false);

        //test ec sign and verify
        test_pki_sign_verify(&core, token, "ec-224", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-256", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-384", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-521", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-224-bad-key-name", "rusty_vault test".as_bytes(), false);

        //test generate aes-gcm key
        test_pki_generate_key_case(&core, token, "aes-gcm-128", "aes-gcm", 128, true, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-192", "aes-gcm", 192, true, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-256", "aes-gcm", 256, true, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-128-internal", "aes-gcm", 128, false, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-192-internal", "aes-gcm", 192, false, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-256-internal", "aes-gcm", 256, false, true);
        test_pki_generate_key_case(&core, token, "aes-gcm-128", "aes-gcm", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-gcm-128-bad-type", "aes-gcmm", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-gcm-128-bad-bits", "aes-gcm", 129, true, false);

        //test aes-gcm encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-128", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-192", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-256", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-256-bad-key-name", "rusty_vault test".as_bytes(), false);

        //test generate aes-cbc key
        test_pki_generate_key_case(&core, token, "aes-cbc-128", "aes-cbc", 128, true, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-192", "aes-cbc", 192, true, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-256", "aes-cbc", 256, true, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-128-internal", "aes-cbc", 128, false, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-192-internal", "aes-cbc", 192, false, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-256-internal", "aes-cbc", 256, false, true);
        test_pki_generate_key_case(&core, token, "aes-cbc-128", "aes-cbc", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-cbc-128-bad-type", "aes-cbcc", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-cbc-128-bad-bits", "aes-cbc", 129, true, false);

        //test aes-cbc encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-128", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-192", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-256", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-256-bad-key-name", "rusty_vault test".as_bytes(), false);

        //test generate aes-ecb key
        test_pki_generate_key_case(&core, token, "aes-ecb-128", "aes-ecb", 128, true, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-192", "aes-ecb", 192, true, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-256", "aes-ecb", 256, true, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-128-internal", "aes-ecb", 128, false, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-192-internal", "aes-ecb", 192, false, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-256-internal", "aes-ecb", 256, false, true);
        test_pki_generate_key_case(&core, token, "aes-ecb-128", "aes-ecb", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-ecb-128-bad-type", "aes-ecbb", 128, true, false);
        test_pki_generate_key_case(&core, token, "aes-ecb-128-bad-bits", "aes-ecb", 129, true, false);

        //test aes-ecb encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-128", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-192", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-256", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-256-bad-key-name", "rusty_vault test".as_bytes(), false);
    }

    fn test_pki_import_key(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();
        //test import rsa key
        test_pki_import_key_case(
            &core,
            token,
            "rsa-2048-import",
            "rsa",
            2048,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/K85aluWn5Pkl
HZ5Ye59UkY7S5dLLBSOXpVyECniTpYi08jK0mwP3D+xqgDvS7OBEK2OVO+eUSWCe
tNHGA/u00HeeADVTNaZK7f2+1KQPkmernOecRU0xbl59ScSOzDDYXMKIhoRs6Neu
qw+jRTuW0t9/UOmni1pN+w9i5z9Lmz0qMsSaPDoy1JqajZoTyzJz30ftN/kEg75T
uhwczIzyKPib/IzvsgoPq6ZtVFx9hVEU6SkaKu3jLrxEIpwAROn0fIrcNuOE+VxY
tpGrBFheD0qbEqOLtMgUYAMWWG86tqWBOBxEnRSEmxhPDLqhu6a4yfBKtwL1JA1e
PeuiEEKJAgMBAAECggEAFHIZx0bajVrSqf1hc+LWLGQcQNezSY2lUVuDqgbj/3KA
TPiW+LRC4ne8WBBFQFlKNlrnncyC3Nv+LpXLK7Y9rjMaNUvzaBCrANo0PbvInMu9
NQr6cGmvCFQ0BzVOWtwMIKUcacqX5if+9/Tenskm8YoLEjbz+RHRLi7lkIqH5/d6
lIJAss5Q/u3D9uTP0ngmztG65IV0vHacn0S3zyOZ7DD+MJwk4GUpYxTtgkFIzuDH
aQgkYcjJeNNWcOesEHs0u1Nqt9GlPyScde/jcblNPMdkBuu1vP0gxjCNdRVu9ZE5
x7V9w2buKFwPIS+Hpv35t/0qvcoYDq1Vg1wj6VUVewKBgQDgv0pq1gwkvcZCttEb
EIitqlQ2y0HH7TdiMB317U2wmLwPmVQ2b1gTD+cHNWE9y1F9rSVeDUfcizm9qvDk
kjNOAfXRt5aFi2a03DKlGY57k6o9sp3qqvESEoryzUOUTUvYe9S7nXZ7B8/Pv0OE
2yyEiCg4XtHTRYPLMqbGp359OwKBgQDZwT/ahzYM7RZex9i3BHpuqs6m9ig7W2oM
7H1Qd4FOOa1lnnq5+/CXDH258OmqANvie/wcD/eQ/tvKIrUfm6DRBvSul2Bbae5F
GJxLttPFqxCiGgWhPW4EWdFgHXCTmMd3gOByklfw1dMZkjor2kJJSi8kPvfWUKgM
oCyZ7aiTCwKBgFmnFSl/D0MMzOzJ/qocM1mLi6J7/FajYydw6FK1AfvDQam7UWOR
kQGxo0g12/+Jfo1yp2hYReVNSJBHg2a6h2rDz2qEILBPBn55JF7FzhevtQZ9nQ8C
d73s1a67gQzEtM+7vgXFb4DugdBujKGPyLdplRm/gVYU8dj58JtoL0YHAoGBAMyi
QvOGJVE4bNFdVVeIqdXeRp24rk45tgu3InzAEZAFu+HHcOXe0VXhszVOJQhSDlFk
2qM0jh6AouPuge/WPOaydrasIy1E+1mLqzWr9o/IFrV/ZtMD+6OzFIQSpnzOEoVH
Y6XHyUTWbK+XL3uOfMSLJooVcqrA2WwkCkYNhWHJAoGBANRT1KPQP0+Tlc+8FoGa
q2Kt71bpNXUzj5Vi/Ikgqm0z943hAvBKIvxY2SPdybvSxk9YeUXhB88cApdepRzc
4hNAvCtpiAQHbH5P9dpDXx6xbr1kT/z5iKe3VzxnEyLlm6yEItoq1k0ZvpyQO+W4
bwtnhIcuKu7aG0qI2abuLtNI
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "rsa-3072-import",
            "rsa",
            3072,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
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
Do5o32GEcxbLo+woXez/9og=
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "rsa-4096-import",
            "rsa",
            4096,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
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
srlAra2xKovU8At81EhC3oarMYLbY9w=
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "rsa-4096-import",
            "rsa",
            4096,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
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
srlAra2xKovU8At81EhC3oarMYLbY9w=
-----END PRIVATE KEY-----
"#,
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "rsa-4096-import-bad-type",
            "rsaa",
            4096,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDonanogPRAGLwJ
Bg1EWDgaqJlQLnb7TrvtBzKCLjtw6ssi/1Q1Oldsw6+QEcDOUl5Z+p2SgyT9Ciq+
eXZQ31TxSppmjyQ1E7xsUk33+TBt8Clcw7sXG0MT7CI+q4s356bJ5IF7O5Sz38Lj
RC2svmE6ptWO+lGtZZTUM4nKs6TWOo/uwfg1OzmwIbFhZsy0l1cF6DO8XKI0L2I8
MjNCZ6mUh7fYfREuXzX/rnZI8Kc4cQWaGfxHGXkXzmW0WQ3K7EfdXgdP9xAeTmvJ
sSWlUVsrxo3+IHGjxExrAjB7xLCl778Nff+MVErt+4aveWocrNHOyXgfYHijyjxl
x0BbjNmPiiBmtaApE950VNzmaoj7B+OrC4SY2yxVjnSOoGo0i08wJIIwYVZQBSwI
yFECMzQupSQfo7/AeIhtXzKRtVHgI6M08IqRIiirqA0x62HQmFmjny3cWhUSHSaJ
fcO0YLThCIjbyw8HtfMyHH3whFrX+hOvgEpC5yabwoqs5PseEAJ7vkOrsfo5/61R
kRrwqonXD68CBwRXWwuGWlxPGRjBt9EMRh7tPTAQD5v5u4ZI1jDsAF24pIPMDAQs
AhqahX+5zsNgIaY2YIBhMcu90eCqqUc9oHQ3l5jOYoGyfI58Vs3N5TEyGYPCu2Es
FJKXNoU8NhH77Y+yWSkxCA20MB6lsQIDAQABAoICABoREOktCjHkk62vL+1otWDH
Y+bITiz7NbPqCo7r/1038muJkTYlw4Y8p3/NfX2hXVFX9DBm4c45RXDyy39kh3BC
m+rCP5xzCbpZvsL6+aJYN0pd5KlCNNIWs/+x2Xf6TYZyRNA6bP97I6u0CCpDa0HX
UDcldeGocHUXEWnVl7Mp/NcUhWvxpxVFsUro6ieSjf3rd2C0QLj4VlnIhlX6p9Yt
HzzzRumbYcG1GywxS4vXnnkWUF7nS9qPFnaPRCxpLeRwlQEw/m1m/E0tvLo5062k
ImVH3XQsmyOiqywzblgp9Y7df7WJ/JuOhBlF0c5Ez34MtZlOhjZUg1Akc+HOdtKY
RHPBk7Ixtg/PHRK/+nS/+7JqQ6SlDdwq6yarm0nghwcgmp+xC9Z4PgUpXO0RCoMi
zwMSKtvlH1C8+dtaVIocPco9SRINV8WeiLcIM6IRkdvS9O+VqgBvjs/79r4iulqZ
CroRUwaFVzrwJ/HDSIJMJDINdBnknPoETCW5fJKw7nO+sjp2W95Y8gtUT/Z2zv+u
Ph5yUvFIuf9Wetl9PxAd4XkWZXUzSNKpxMbOCA1PofpLL3i9AB4cYSGpiUPFFoHO
T/j2bEbswxGARzPe20JCmufqf22c3z8ulgusVLS67ds7vh6m29mvZqyi6uvmF5QB
17Ji53b/lHrLJg/kkwjBAoIBAQD4iusLH+KhrE34f/FjkUQOMXqXy9gYZPlS3PpY
frYdvLw6K2NXb15fV+OfwH7cdNBw5kQtx4odasw2cKxcbgyS4eoQLWnxLCTWQuOo
RnGEvQWnUefccMWXsjdmvJQlbCB0WhWGgVorEGrN2W3d4vaVA6zahSQ7m8GvT5wz
1h6ahQylOhAzAzdpewymET5QlAsyX54pAjTAUOXQzbxTabbPNli0mVa1xi/a1LKv
J0GngUP/rXFWAvnDjbZsfsyRa5947HRt5yvwGgSj+3/8q6CMlSA8IjRgFVEJAtUS
t/OkLBzXZ7AdRgD1EzSpI3YXFdvkMgMJQQxr5qmRsSshP7RXAoIBAQDvmGkM9dNd
RZ4X3tgguIaldm2YUir8I1gFy2SjUe0BVxDuLqI+fCebE0J2BEwxrEJpJskDtMtF
h/PVSSKNUhpe12A98qYhlczfyqtfLfnyAsX1C0YbtEK041NjM/NIX7Zr1xoQyRT9
TL0CsLavl3oNRZ2j4d2rTYyBcn1A9blFfCfOppG3E0pd2f+JmTdp8ap/ITas4Rpj
rYSiTMMDS0zT6agjsur/8/yPbgUjRzU02JUjfEXBpT6bCKdom+X+UTacnBri+JRx
Kr6ZOPNxZzJX6hRHnrJ5b4x75JKYHeMQPaRy9/6+hj5QnC/5ZJLdgFBf986xNcM9
uzIkWD8Q//E3AoIBAQCp/pI+/KMNA4Yc9p2LBXuv3YXFN2ZpYP7q/zu3tYsokcOI
Yc7Dqee5fKqyxH3AmaFL5yMw0K8V6csdXTl2ysqM2Do4sGcqzo+vgPanTO8t4/9u
7uWQcA2l8P5VpZwKcIdOLaNVaTncBJGYlCPCRQ904puiprgekS0LlH75MXWjKGd6
x1j3GzcWTVRcbaTahjeWT7IkyF5+P5bAl0c9IiwoVDqd49db4t8uZJaGmGoegJqa
0O2Y79YXO+FPGfcfa6YallgYJ6p0wcb0xftHPbhFD2aJ2rdKFKplaGuGLw1U99sO
NdxOWWgkN+un2BpYNdo9nTtYZAZz8sN+Y9hlGGZnAoIBAAGqxdBZRYc4nMj9u/M+
VXGBSXHt4G6wsEQaDjE0uLlxqaR+npJgusXRdHzturn9wNiKdIuaDnAFaiTpxVvG
Xniadwj3T0CckjhcaKTY5QxSCJ6T3YED2BL6IfJmwiKWx+YoMP485/B7QDVslVjT
bP36pgYl5Cz09S1RZp21F/zryDsf3ZOwhqvwgF6suj36eH059e9uAYkABBQ9BH5Z
X8d5sLnO3OO7Bt7YnSCJtk0P1LnSe4nFZJIflUqdCxSh7Ada7rT1ldLTwU+/nbIE
Tc1ey5VT/Vnq9MdH5903GAVc6HAEWblppbVZ4NuTX5I6+lQwnTeOcDVVwBuQoZ+0
qDECggEBAIwdjxe5PVCk4dNZh5tiGta+IEeiF7nTrqFJrlGYQ5HUPUcD8chupAAB
LdHdzlsJUyCsqAHUxk74CYPMmG2w4+Lyr8siTfDvTW5f9Q43vGAGzRF0oGyQNBHv
VTNPCI2QzRBXneLn+hWcDda3Lgg0IMpPQEXJKOak3kOFnboSwvsN8aP2/LrLBKaV
V6B7Y5GlEch1VTZMb8tyAeLa1PIFFGoJb7mfiZqIfRqrRbQ9kzVBzyeiHAc06VvJ
CMWOmQT9pmXTLLmS4KDU+ktQao+U+LXvgYzhzFo9KqkVeNkifppVFZBW5sC/DQbd
srlAra2xKovU8At81EhC3oarMYLbY9w=
-----END PRIVATE KEY-----
"#,
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "rsa-4096-import-bad-pem",
            "rsaa",
            4096,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
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
srlAra2xKovU8At81EhC3oarMYLbY9w=
-----END PRIVATE KEY-----
"#,
            false,
        );

        //test rsa sign and verify
        test_pki_sign_verify(&core, token, "rsa-2048-import", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "rsa-3072-import", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "rsa-4096-import", "rusty_vault test".as_bytes(), true);

        //test import ec key
        test_pki_import_key_case(
            &core,
            token,
            "ec-224-import",
            "ec",
            224,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBzsiBoYW2wy95WsH51cIW90
l5jP3LyA//F/qHE5oTwDOgAEasjtLNpFz6+08WsxkDppMANKXPfaiIzvSfLMFIZU
K9bNL/xrK2WENeATjX1eZE9JZtjDwnAqlJM=
-----END PRIVATE KEY-----
                                "#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "ec-256-import",
            "ec",
            256,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfSJ3DnUokwFD0QtnEE1f
e0Y20qDAjcYbwFwkWBkWcy+hRANCAATKrAXdOc0ufhMk8225jX+C9a/WfjNIp7lu
AAOYNTNA2jpy34lQ2zlBLIoaTuxXtg6mWvfITYPGrpWorcPTYzG+
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "ec-384-import",
            "ec",
            384,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDY0x5JtPPUfipvnd7P
C6vZfNzkyBRCiwzGbFY1MH39ZC4TfNx0t5SiADPDNv4g1y6hZANiAASMgIt8fVVY
TKSYqB3QPPoSWhfvlq1iSdarRYfH+6S9dRpeaf+xnnVVMD8iqmUBOdl0UZZHOOt6
+JJpUl0cZF9t6E92N4SaXaFI3ZLzYziaMZU1MSTWJZyJvi3vswqHEYU=
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "ec-521-import",
            "ec",
            521,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA/PzzOHksK0r/Z/82
43IOFCYFjhOL08+cFGElJjHfubjTGhzr1jDHwwnMnd7LAOk+M9395uJjwXMrW5GN
qWeY8cWhgYkDgYYABAG44vWoqZdKP+nGTDNcmK2phS9/TWfHrCqxJAckyINLYwuE
UdkF6MbAwJJOPnBntqZOt83iUtFKUWxy0iFPQVn49QHP/yT+G/cz3qjx7TkFP+4W
jmQbXbxLGIvSIZoscho/LSWyyct4CBPbPplopiMTgDN1MA7mFvT2TYAxFJA0rVWk
Fw==
-----END PRIVATE KEY-----
"#,
            true,
        );
        test_pki_import_key_case(&core, token, "ec-521-import", "ec", 521, "", "same key name", false);
        test_pki_import_key_case(
            &core,
            token,
            "ec-521-import-bad-type",
            "ecc",
            521,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA/PzzOHksK0r/Z/82
43IOFCYFjhOL08+cFGElJjHfubjTGhzr1jDHwwnMnd7LAOk+M9395uJjwXMrW5GN
qWeY8cWhgYkDgYYABAG44vWoqZdKP+nGTDNcmK2phS9/TWfHrCqxJAckyINLYwuE
UdkF6MbAwJJOPnBntqZOt83iUtFKUWxy0iFPQVn49QHP/yT+G/cz3qjx7TkFP+4W
jmQbXbxLGIvSIZoscho/LSWyyct4CBPbPplopiMTgDN1MA7mFvT2TYAxFJA0rVWk
Fw==
-----END PRIVATE KEY-----
"#,
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "ec-521-import-bad-pem",
            "ec",
            521,
            "",
            r#"
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA/PzzOHksK0r/Z/82
43IOFCYFjhOL08+cFGElJjHfubjTGhzr1jDHwwnMnd7LAOk+M9395uJjwXMrW5GN
qWeY8cWhgYkDgYYABAG44vWoqZdKP+nGTDNcmK2phS9/TWfHrCqxJAckyINLYwuE
UdkF6MbAwJJOPnBntqZOt83iUtFKUWxy0iFPQVn49QHP/yT+G/cz3qjx7TkFP+4W
jmQbXbxLGIvSIZoscho/LSWyyct4CBPbPplopiMTgDN1MA7mFvT2TYAxFJA0rVWkaabb
Fw==
xxxxxxxxxxxxxx
-----END PRIVATE KEY-----
        "#,
            false,
        );

        //test ec sign and verify
        test_pki_sign_verify(&core, token, "ec-224-import", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-256-import", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-384-import", "rusty_vault test".as_bytes(), true);
        test_pki_sign_verify(&core, token, "ec-521-import", "rusty_vault test".as_bytes(), true);

        //test import aes-gcm key
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-128-import",
            "aes-gcm",
            128,
            "1c499088cddd0382918bd5650718533d",
            "cfe0f571fe695c6a4c5e34339d32eb3c",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-192-import",
            "aes-gcm",
            192,
            "1c499088cddd0382918bd5650718533d",
            "3077fdca16350c85c354a700bbc127972dafe2138874cdea",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-256-import",
            "aes-gcm",
            256,
            "1c499088cddd0382918bd5650718533d",
            "6349e3032b690f2fe61a824746ac3ab05c1829a4147f4891f595dfb19cddfd06",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-256-import",
            "aes-gcm",
            256,
            "1c499088cddd0382918bd5650718533d",
            "same key name",
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-256-import-bad-type",
            "aes-gcmm",
            256,
            "1c499088cddd0382918bd5650718533d",
            "6349e3032b690f2fe61a824746ac3ab05c1829a4147f4891f595dfb19cddfd06",
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-gcm-256-import-bad-hex",
            "aes-gcm",
            256,
            "1c499088cddd0382918bd5650718533d",
            "aa6349e3032b690f2fe61a824746ac3ab05c1829a4147f4891f595dfb19cddfd06",
            false,
        );

        //test aes-gcm encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-128-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-192-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-gcm-256-import", "rusty_vault test".as_bytes(), true);

        //test import aes-cbc key
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-128-import",
            "aes-cbc",
            128,
            "1c499088cddd0382918bd5650718533d",
            "77628ff2c35adc7efdecfb0e86a4576f",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-192-import",
            "aes-cbc",
            192,
            "1c499088cddd0382918bd5650718533d",
            "807f5f15d2924f104700f058030298c8591d0f6b5163b333",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-256-import",
            "aes-cbc",
            256,
            "1c499088cddd0382918bd5650718533d",
            "521fc4bb8ee6015ac5a6e3e611854aa7608a17413f72ee007e799dac303853e1",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-256-import",
            "aes-cbc",
            256,
            "1c499088cddd0382918bd5650718533d",
            "same key name",
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-256-import-bad-type",
            "aes-cbcc",
            256,
            "1c499088cddd0382918bd5650718533d",
            "521fc4bb8ee6015ac5a6e3e611854aa7608a17413f72ee007e799dac303853e1",
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-cbc-256-import-bad-hex",
            "aes-cbc",
            256,
            "1c499088cddd0382918bd5650718533d",
            "21521fc4bb8ee6015ac5a6e3e611854aa7608a17413f72ee007e799dac303853e1",
            false,
        );

        //test aes-cbc encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-128-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-192-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-cbc-256-import", "rusty_vault test".as_bytes(), true);

        //test import aes-ecb key
        test_pki_import_key_case(
            &core,
            token,
            "aes-ecb-128-import",
            "aes-ecb",
            128,
            "",
            "38a1f9ad74562db696872cbfa10cc46e",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-ecb-192-import",
            "aes-ecb",
            192,
            "",
            "b80f65a5a334e583bafd18d2e86667384ae16cb0467982de",
            true,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-ecb-256-import",
            "aes-ecb",
            256,
            "",
            "95b622ebf838b0b8b4cc60635333f87f9b10bcbe340b710020a6e9789156c052",
            true,
        );
        test_pki_import_key_case(&core, token, "aes-ecb-256-import", "aes-ecb", 256, "", "same key name", false);
        test_pki_import_key_case(
            &core,
            token,
            "aes-ecb-256-import-bad-type",
            "aes-ecbb",
            256,
            "",
            "95b622ebf838b0b8b4cc60635333f87f9b10bcbe340b710020a6e9789156c052",
            false,
        );
        test_pki_import_key_case(
            &core,
            token,
            "aes-ecb-256-import-bad-hex",
            "aes-ecb",
            256,
            "",
            "2295b622ebf838b0b8b4cc60635333f87f9b10bcbe340b710020a6e9789156c052",
            false,
        );

        //test aes-gcm encrypt and decrypt
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-128-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-192-import", "rusty_vault test".as_bytes(), true);
        test_pki_encrypt_decrypt(&core, token, "aes-ecb-256-import", "rusty_vault test".as_bytes(), true);
    }

    #[test]
    fn test_pki_module() {
        let dir = env::temp_dir().join("rusty_vault_pki_module");
        assert!(fs::create_dir(&dir).is_ok());
        defer! (
            assert!(fs::remove_dir_all(&dir).is_ok());
        );

        let mut root_token = String::new();
        println!("root_token: {:?}", root_token);

        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(dir.to_string_lossy().into_owned()));

        let backend = physical::new_backend("file", &conf).unwrap();

        let barrier = barrier_aes_gcm::AESGCMBarrier::new(Arc::clone(&backend));

        let c = Arc::new(RwLock::new(Core { physical: backend, barrier: Arc::new(barrier), ..Default::default() }));

        {
            let mut core = c.write().unwrap();
            assert!(core.config(Arc::clone(&c), None).is_ok());

            let seal_config = SealConfig { secret_shares: 10, secret_threshold: 5 };

            let result = core.init(&seal_config);
            assert!(result.is_ok());
            let init_result = result.unwrap();
            println!("init_result: {:?}", init_result);

            let mut unsealed = false;
            for i in 0..seal_config.secret_threshold {
                let key = &init_result.secret_shares[i as usize];
                let unseal = core.unseal(key);
                assert!(unseal.is_ok());
                unsealed = unseal.unwrap();
            }

            root_token = init_result.root_token;

            assert!(unsealed);
        }

        {
            println!("root_token: {:?}", root_token);
            test_pki_config_ca(Arc::clone(&c), &root_token);
            test_pki_config_role(Arc::clone(&c), &root_token);
            test_pki_issue_cert(Arc::clone(&c), &root_token);
            test_pki_generate_key(Arc::clone(&c), &root_token);
            test_pki_import_key(Arc::clone(&c), &root_token);
        }
    }
}
