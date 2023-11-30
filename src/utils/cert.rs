use std::time::{SystemTime, UNIX_EPOCH};
use openssl::{
    x509::{
        X509, X509Builder, X509Name, X509NameBuilder, X509Extension,
        extension::{
            KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier, AuthorityKeyIdentifier,
            BasicConstraints,
        },
    },
    pkey::{PKey, Private},
    rsa::Rsa,
    ec::{EcGroup, EcKey},
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    asn1::{Asn1OctetString, Asn1Time},
};
use libc::c_int;
use lazy_static::lazy_static;
use foreign_types::{ForeignType};
use serde::{ser::SerializeTuple, Serialize, Serializer, Deserialize, Deserializer};
use serde_bytes::ByteBuf;
use crate::{
    errors::RvError,
};

lazy_static! {
    static ref X509_DEFAULT: X509 = X509Builder::new().unwrap().build();
    static ref PKEY_DEFAULT: PKey<Private> = PKey::generate_ed25519().unwrap();
}

extern "C" {
    pub fn X509_check_ca(x509: *mut openssl_sys::X509) -> c_int;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBundle {
    #[serde(serialize_with = "serialize_x509", deserialize_with = "deserialize_x509")]
    pub certificate: X509,
    #[serde(serialize_with = "serialize_vec_x509", deserialize_with = "deserialize_vec_x509")]
    pub ca_chain: Vec<X509>,
    #[serde(serialize_with = "serialize_pkey", deserialize_with = "deserialize_pkey")]
    pub private_key: PKey<Private>,
    #[serde(default)]
    pub private_key_type: String,
    #[serde(default)]
    pub serial_number: String,
}

fn serialize_x509<S>(cert: &X509, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(&cert.to_pem().unwrap())
}

fn deserialize_x509<'de, D>(deserializer: D) -> Result<X509, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pem_bytes: &[u8] = &ByteBuf::deserialize(deserializer)?;
    X509::from_pem(pem_bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_vec_x509<S>(x509_vec: &[X509], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut tuple = serializer.serialize_tuple(x509_vec.len())?;
    for x509 in x509_vec {
        tuple.serialize_element(&x509.to_pem().unwrap())?;
    }
    tuple.end()
}

pub fn deserialize_vec_x509<'de, D>(deserializer: D) -> Result<Vec<X509>, D::Error>
where
    D: Deserializer<'de>,
{
    let pem_bytes_vec: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
    let mut x509_vec = Vec::new();
    for pem_bytes in pem_bytes_vec {
        let x509 = X509::from_pem(&pem_bytes).map_err(serde::de::Error::custom)?;
        x509_vec.push(x509);
    }
    Ok(x509_vec)
}

fn serialize_pkey<S>(key: &PKey<openssl::pkey::Private>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(&key.private_key_to_pem_pkcs8().unwrap())
}

fn deserialize_pkey<'de, D>(deserializer: D) -> Result<PKey<openssl::pkey::Private>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    //let pem_bytes: &[u8] = Deserialize::deserialize(deserializer)?;
    let pem_bytes: &[u8] = &ByteBuf::deserialize(deserializer)?;
    PKey::private_key_from_pem(pem_bytes).map_err(serde::de::Error::custom)
}

pub fn is_ca_cert(cert: &X509) -> bool {
    unsafe {
        X509_check_ca(cert.as_ptr()) != 0
    }
}

impl Default for CertBundle {
    fn default() -> Self {
        CertBundle {
            certificate: X509_DEFAULT.clone(),
            ca_chain: Vec::new(),
            private_key: PKEY_DEFAULT.clone(),
            private_key_type: String::new(),
            serial_number: String::new(),
        }
    }
}

impl CertBundle {
    pub fn new() -> Self {
        CertBundle::default()
    }

    pub fn verify(&self) -> Result<(), RvError> {
        let cert_pubkey = self.certificate.public_key()?;
        if !self.private_key.public_eq(&cert_pubkey) {
            return Err(RvError::ErrPkiCertKeyMismatch);
        }

        let cert_chain = self.get_cert_chain();

        if cert_chain.len() > 0 {
            for (i, ca_cert) in cert_chain[1..].iter().enumerate() {
                if !is_ca_cert(ca_cert) {
                    return Err(RvError::ErrPkiCertIsNotCA);
                }

                let authority_key_id = cert_chain[i].subject_key_id();
                let subject_key_id = ca_cert.subject_key_id();

                if authority_key_id.is_none() || subject_key_id.is_none() {
                    return Err(RvError::ErrPkiCaExtensionIncorrect);
                }

                if authority_key_id.unwrap().as_slice() != subject_key_id.unwrap().as_slice() {
                    return Err(RvError::ErrPkiCertChainIncorrect);
                }
            }
        }

        Ok(())
    }

    pub fn get_cert_chain(&self) -> Vec<&X509> {
        let mut cert_chain = Vec::new();

        cert_chain.push(&self.certificate);

        if self.ca_chain.len() > 0 {
            // Root CA puts itself in the chain
            if self.ca_chain[0].serial_number() != self.certificate.serial_number() {
                cert_chain.extend(self.ca_chain.iter());
            }
        }

        cert_chain
    }
}

pub struct Certificate {
    pub version: i32,
    pub serial_number: BigNum,
    pub issuer: X509Name,
    pub subject: X509Name,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub extensions: Vec<X509Extension>,
    pub subject_key_id: Asn1OctetString,
    pub authority_key_id: Asn1OctetString,
    pub dns_sans: Vec<String>,
    pub email_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    pub uri_sans: Vec<String>,
    pub is_ca: bool,
    pub key_type: String,
    pub key_bits: u32,
}

impl Default for Certificate {
    fn default() -> Self {
        let mut sn = BigNum::new().unwrap();
        sn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        Self {
            version: 3,
            serial_number: sn,
            issuer: X509NameBuilder::new().unwrap().build(),
            subject: X509NameBuilder::new().unwrap().build(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now(),
            extensions: Vec::new(),
            subject_key_id: Asn1OctetString::new_from_bytes("".as_bytes()).unwrap(),
            authority_key_id: Asn1OctetString::new_from_bytes("".as_bytes()).unwrap(),
            dns_sans: Vec::new(),
            email_sans: Vec::new(),
            ip_sans: Vec::new(),
            uri_sans: Vec::new(),
            is_ca: false,
            key_type: "rsa".to_string(),
            key_bits: 2048,
        }
    }
}

impl Certificate {
    pub fn to_x509(&mut self,
                   ca_cert: &X509,
                   ca_key: &PKey<Private>,
                   private_key: &PKey<Private>
    ) -> Result<X509, RvError> {
        let mut builder = X509::builder()?;
        builder.set_version(self.version)?;
        let serial_number = self.serial_number.to_asn1_integer()?;
        builder.set_serial_number(&serial_number)?;
        builder.set_subject_name(&self.subject)?;
        builder.set_issuer_name(ca_cert.subject_name())?;
        builder.set_pubkey(private_key)?;

        let not_before_dur = self.not_before.duration_since(UNIX_EPOCH)?;
        let not_before_sec = not_before_dur.as_secs() - 30;
        let not_before = Asn1Time::from_unix(not_before_sec as i64)?;
        builder.set_not_before(&not_before)?;

        let not_after_dur = self.not_after.duration_since(UNIX_EPOCH)?;
        let not_after_sec = not_after_dur.as_secs();
        let not_after = Asn1Time::from_unix(not_after_sec as i64)?;
        builder.set_not_after(&not_after)?;

        let mut san_ext = SubjectAlternativeName::new();
        for dns in &self.dns_sans {
            san_ext.dns(dns.as_str());
        }

        for email in &self.email_sans {
            san_ext.email(email.as_str());
        }

        for ip in &self.ip_sans {
            san_ext.ip(ip.as_str());
        }

        for uri in &self.uri_sans {
            san_ext.uri(uri.as_str());
        }

        builder.append_extension(san_ext.build(&builder.x509v3_context(Some(ca_cert), None))?)?;

        for ext in &self.extensions {
            builder.append_extension2(ext)?;
        }

        if self.is_ca {
            builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        }

        builder.append_extension(KeyUsage::new()
                                 .critical()
                                 .non_repudiation()
                                 .digital_signature()
                                 .key_encipherment()
                                 .build()?)?;

        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(ca_cert), None))?;
        builder.append_extension(subject_key_id)?;

        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(ca_cert), None))?;
        builder.append_extension(authority_key_id)?;

        builder.sign(ca_key, MessageDigest::sha256())?;

        Ok(builder.build())
    }

    pub fn to_cert_bundle(&mut self,
                          ca_cert: &X509,
                          ca_key: &PKey<Private>)
    -> Result<CertBundle, RvError> {
        let key_bits = self.key_bits;
        let priv_key = match self.key_type.as_str() {
            "rsa" => {
                if key_bits != 2048 && key_bits != 3072 && key_bits != 4096 {
                    return Err(RvError::ErrPkiKeyBitsInvalid);
                }
                let rsa_key = Rsa::generate(key_bits)?;
                let pkey = PKey::from_rsa(rsa_key)?;
                pkey
            },
            "ec" => {
                let curve_name = match key_bits {
                    224 => Nid::SECP224R1,
                    256 => Nid::SECP256K1,
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => {
                        return Err(RvError::ErrPkiKeyBitsInvalid);
                    }
                };
                let ec_group = EcGroup::from_curve_name(curve_name)?;
                let ec_key = EcKey::generate(ec_group.as_ref())?;
                let pkey = PKey::from_ec_key(ec_key)?;
                pkey
            },
            _ => {
                return Err(RvError::ErrPkiKeyTypeInvalid);
            }
        };

        let cert = self.to_x509(ca_cert, ca_key, &priv_key)?;
        let serial_number = cert.serial_number().to_bn()?;
        let serial_number_hex = serial_number.to_hex_str()?;
        let serial_number_hex = serial_number_hex.chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(":");

        let cert_bundle = CertBundle {
            certificate: cert,
            ca_chain: vec![ca_cert.clone()],
            private_key: priv_key.clone(),
            private_key_type: self.key_type.clone(),
            serial_number: serial_number_hex.to_lowercase(),
        };

        Ok(cert_bundle)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use humantime::parse_duration;
    use openssl::rsa::Rsa;

    #[test]
    fn test_create_certificate() {
        let not_before = SystemTime::now();
        let not_after = not_before + parse_duration("30d").unwrap();
        let mut subject_name  = X509NameBuilder::new().unwrap();
        subject_name.append_entry_by_text("C", "CN").unwrap();
        subject_name.append_entry_by_text("ST", "ZJ").unwrap();
        subject_name.append_entry_by_text("L", "HZ").unwrap();
        subject_name.append_entry_by_text("O", "Ant-Group").unwrap();
        subject_name.append_entry_by_text("CN", "www.test.com").unwrap();
        let subject = subject_name.build();

        let mut cert = Certificate {
            not_before: not_before,
            not_after: not_after,
            subject: subject,
            dns_sans: vec!["www.test.com".to_string(), "test.com".to_string()],
            email_sans: vec!["www@test.com".to_string(), "xx@test.com".to_string()],
            ip_sans: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            uri_sans: vec!["test/".to_string(), "xx/test/".to_string()],
            ..Certificate::default()
        };

        let ca_cert_pem = r#"
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
-----END CERTIFICATE-----
        "#;
        let ca_key_pem = r#"
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
-----END PRIVATE KEY-----
        "#;
        let ca_cert = X509::from_pem(ca_cert_pem.as_bytes()).unwrap();
        let ca_key = PKey::private_key_from_pem(ca_key_pem.as_bytes()).unwrap();

        let rsa_key = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa_key).unwrap();

        let x509 = cert.to_x509(&ca_cert, &ca_key, &pkey);
        assert!(x509.is_ok());
        let x509_pem = x509.unwrap().to_pem().unwrap();
        println!("x509_pem: \n{}", String::from_utf8_lossy(&x509_pem));
        let cert_bundle = cert.to_cert_bundle(&ca_cert, &ca_key);
        assert!(cert_bundle.is_ok());
        let cert_bundle = cert_bundle.unwrap();
        assert!(cert_bundle.private_key.public_eq(&cert_bundle.certificate.public_key().unwrap()));
    }
}
