use std::{
    ops::Deref,
    sync::{Arc, RwLock, atomic::AtomicU64},
    time::{Duration},
    collections::HashMap,
};
use crate::{
    new_path, new_path_internal,
    new_secret, new_secret_internal,
    new_logical_backend, new_logical_backend_internal,
    logical::{
        Backend, LogicalBackend, Request, Response,
        Operation, Path, PathOperation, Field, FieldType,
        secret::Secret,
    },
    modules::Module,
    core::Core,
    errors::RvError,
};

pub mod path_roles;
pub mod path_config_ca;
pub mod path_config_crl;
pub mod path_fetch;
pub mod path_issue;
pub mod path_revoke;

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
                core: core,
                cert_count: AtomicU64::new(0),
                revoked_cert_count: AtomicU64::new(0),
            })
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
    use super::*;
    use std::{
        env,
        fs,
        time::{SystemTime, UNIX_EPOCH},
        default::Default,
        sync::{Arc, RwLock},
        collections::HashMap,
    };
    use serde_json::{json, Value, Map};
    use go_defer::defer;
    use openssl::{
        x509::X509,
        pkey::PKey,
        asn1::Asn1Time,
    };
    use crate::{
        storage::{physical, barrier_aes_gcm},
        core::{Core, SealConfig},
        logical::{Operation, Request},
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

    fn test_write_api(core: &Core, token: &str, path: &str, is_ok: bool, data: Option<Map<String, Value>>) -> Result<Option<Response>, RvError> {
        let mut req = Request::new(path);
        req.operation = Operation::Write;
        req.client_token = token.to_string();
        req.body = data;

        let resp = core.handle_request(&mut req);
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
        }).as_object().unwrap().clone();

        let resp = test_write_api(&core, token, "sys/mounts/pki/", true, Some(mount_data));
        assert!(resp.is_ok());

        let ca_pem_bundle = format!("{}{}", CA_CERT_PEM, CA_KEY_PEM);

        let ca_data = json!({
            "pem_bundle": ca_pem_bundle,
        }).as_object().unwrap().clone();

        // config ca
        let resp = test_write_api(&core, token, "pki/config/ca", true, Some(ca_data));
        assert!(resp.is_ok());
        let resp_ca = test_read_api(&core, token, "pki/ca", true);
        let resp_ca_pem = test_read_api(&core, token, "pki/ca/pem", true);
        let resp_ca_cert_data = resp_ca.unwrap().unwrap().data.unwrap();
        let resp_ca_pem_cert_data = resp_ca_pem.unwrap().unwrap().data.unwrap();
        assert!(resp_ca_cert_data.get("private_key").is_none());
        assert!(resp_ca_pem_cert_data.get("private_key").is_none());
        assert_eq!(resp_ca_cert_data["certificate"].as_str().unwrap(), resp_ca_pem_cert_data["certificate"].as_str().unwrap());
        assert_eq!(resp_ca_cert_data["serial_number"].as_str().unwrap(), resp_ca_pem_cert_data["serial_number"].as_str().unwrap());
        assert_eq!(resp_ca_cert_data["certificate"].as_str().unwrap().trim(), CA_CERT_PEM.trim());
    }

    fn test_pki_config_role(core: Arc<RwLock<Core>>, token: &str) {
        let core = core.read().unwrap();

        // mount pki backend to path: pki/
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
        }).as_object().unwrap().clone();

        // config role
        assert!(test_write_api(&core, token, "pki/roles/test", true, Some(role_data)).is_ok());
        let resp = test_read_api(&core, token, "pki/roles/test", true);
        assert!(resp.as_ref().unwrap().is_some());
        let resp = resp.unwrap();
        assert!(resp.is_some());
        let data = resp.unwrap().data;
        assert!(data.is_some());
        let role_data = data.unwrap();
        assert_eq!(role_data["ttl"].as_u64().unwrap(), 60*24*60*60);
        assert_eq!(role_data["max_ttl"].as_u64().unwrap(), 365*24*60*60);
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

        // mount pki backend to path: pki/
        let dns_sans = vec!["test.com", "a.test.com", "b.test.com"];
        let issue_data = json!({
            "ttl": "10d",
            "common_name": "test.com",
            "alt_names": "a.test.com,b.test.com",
        }).as_object().unwrap().clone();

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
        assert!(priv_key.public_eq(&cert.public_key().unwrap()));
        let serial_number = cert.serial_number().to_bn().unwrap();
        let serial_number_hex = serial_number.to_hex_str().unwrap();
        assert_eq!(cert_data["serial_number"].as_str().unwrap().replace(":", "").to_lowercase().as_str(), serial_number_hex.to_lowercase().as_str());
        let expiration_time = Asn1Time::from_unix(cert_data["expiration"].as_i64().unwrap()).unwrap();
        let ttl_compare = cert.not_after().compare(&expiration_time);
        assert!(ttl_compare.is_ok());
        assert_eq!(ttl_compare.unwrap(), std::cmp::Ordering::Equal);
        let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expiration_ttl = cert_data["expiration"].as_u64().unwrap();
        let ttl = expiration_ttl - now_timestamp;
        let expect_ttl = 10*24*60*60;
        assert!(ttl <= expect_ttl);
        assert!((ttl + 2) > expect_ttl);

        //test fetch cert
        let serial_number_hex = cert_data["serial_number"].as_str().unwrap();
        let resp_lowercase = test_read_api(&core, token, format!("pki/cert/{}", serial_number_hex.to_lowercase().as_str()).as_str(), true);
        let resp_uppercase = test_read_api(&core, token, format!("pki/cert/{}", serial_number_hex.to_uppercase().as_str()).as_str(), true);
        let resp_lowercase_cert_data = resp_lowercase.unwrap().unwrap().data.unwrap();
        let resp_uppercase_cert_data = resp_uppercase.unwrap().unwrap().data.unwrap();
        assert!(resp_lowercase_cert_data.get("private_key").is_none());
        assert!(resp_uppercase_cert_data.get("private_key").is_none());
        assert_eq!(resp_lowercase_cert_data["certificate"].as_str().unwrap(), resp_uppercase_cert_data["certificate"].as_str().unwrap());
        assert_eq!(cert_data["certificate"].as_str().unwrap(), resp_uppercase_cert_data["certificate"].as_str().unwrap());
        assert_eq!(cert_data["serial_number"].as_str().unwrap(), resp_lowercase_cert_data["serial_number"].as_str().unwrap());
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

        let c = Arc::new(RwLock::new(Core {
            physical: backend,
            barrier: Arc::new(barrier),
            ..Default::default()
        }));

        {
            let mut core = c.write().unwrap();
            assert!(core.config(Arc::clone(&c), None).is_ok());

            let seal_config = SealConfig {
                secret_shares: 10,
                secret_threshold: 5,
            };

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
        }
    }
}
