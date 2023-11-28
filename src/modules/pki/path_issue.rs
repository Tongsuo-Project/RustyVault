use std::time::{Duration, SystemTime, UNIX_EPOCH};

use humantime::parse_duration;
use openssl::{asn1::Asn1Time, x509::X509NameBuilder};
use serde_json::{json, Map, Value};

use super::PkiBackendInner;
use crate::{
    errors::RvError,
    logical::{Backend, Request, Response},
    storage::StorageEntry,
    utils,
    utils::{cert, cert::CertBundle},
};

impl PkiBackendInner {
    pub fn issue_cert(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_value = req.get_data("role")?;
        let role_name = role_value.as_str().unwrap();

        let mut common_names = Vec::new();

        let common_name_value = req.get_data("common_name")?;
        let common_name = common_name_value.as_str().unwrap();
        if common_name != "" {
            common_names.push(common_name.to_string());
        }

        let alt_names_value = req.get_data("alt_names");
        if alt_names_value.is_ok() {
            let alt_names_val = alt_names_value.unwrap();
            let alt_names = alt_names_val.as_str().unwrap();
            if alt_names != "" {
                for v in alt_names.split(',') {
                    common_names.push(v.to_string());
                }
            }
        }

        let role = self.get_role(req, &role_name)?;
        if role.is_none() {
            return Err(RvError::ErrPkiRoleNotFound);
        }

        let role_entry = role.unwrap();

        let mut ip_sans = Vec::new();
        let ip_sans_value = req.get_data("ip_sans");
        if ip_sans_value.is_ok() {
            let ip_sans_val = ip_sans_value.unwrap();
            let ip_sans_str = ip_sans_val.as_str().unwrap();
            if ip_sans_str != "" {
                for v in ip_sans_str.split(',') {
                    ip_sans.push(v.to_string());
                }
            }
        }

        let ca_bundle = self.fetch_ca_info(req)?;
        let not_before = SystemTime::now() - Duration::from_secs(10);
        let mut not_after = not_before + parse_duration("30d").unwrap();

        let ttl_value = req.get_data("ttl")?;
        let ttl = ttl_value.as_str().unwrap();
        if ttl != "" {
            let ttl_dur = parse_duration(ttl)?;
            let req_ttl_not_after_dur = SystemTime::now() + ttl_dur;
            let req_ttl_not_after =
                Asn1Time::from_unix(req_ttl_not_after_dur.duration_since(UNIX_EPOCH)?.as_secs() as i64)?;
            let ca_not_after = ca_bundle.certificate.not_after();
            match ca_not_after.compare(&req_ttl_not_after) {
                Ok(ret) => {
                    if ret == std::cmp::Ordering::Less {
                        return Err(RvError::ErrRequestInvalid);
                    }
                    not_after = req_ttl_not_after_dur;
                }
                Err(err) => {
                    return Err(RvError::OpenSSL { source: err });
                }
            }
        }

        let mut subject_name = X509NameBuilder::new().unwrap();
        if role_entry.country.len() > 0 {
            subject_name.append_entry_by_text("C", &role_entry.country).unwrap();
        }
        if role_entry.province.len() > 0 {
            subject_name.append_entry_by_text("ST", &role_entry.province).unwrap();
        }
        if role_entry.locality.len() > 0 {
            subject_name.append_entry_by_text("L", &role_entry.locality).unwrap();
        }
        if role_entry.organization.len() > 0 {
            subject_name.append_entry_by_text("O", &role_entry.organization).unwrap();
        }
        if role_entry.ou.len() > 0 {
            subject_name.append_entry_by_text("OU", &role_entry.ou).unwrap();
        }
        if common_name != "" {
            subject_name.append_entry_by_text("CN", common_name).unwrap();
        }
        let subject = subject_name.build();

        let mut cert = cert::Certificate {
            not_before,
            not_after,
            subject,
            dns_sans: common_names,
            ip_sans,
            key_bits: role_entry.key_bits,
            ..cert::Certificate::default()
        };

        let cert_bundle = cert.to_cert_bundle(&ca_bundle.certificate, &ca_bundle.private_key)?;

        if !role_entry.no_store {
            let serial_number_hex = cert_bundle.serial_number.replace(":", "-").to_lowercase();
            let entry = StorageEntry::new(format!("certs/{}", serial_number_hex).as_str(), &cert_bundle)?;
            req.storage_put(&entry)?;
        }

        let cert_expiration = utils::asn1time_to_timestamp(cert_bundle.certificate.not_after().to_string().as_str())?;
        let ca_chain_pem: String = cert_bundle
            .ca_chain
            .iter()
            .map(|x509| x509.to_pem().unwrap())
            .map(|pem| String::from_utf8_lossy(&pem).to_string())
            .collect::<Vec<String>>()
            .join("");

        let resp_data = json!({
            "expiration": cert_expiration,
            "ca_chain": ca_chain_pem,
            "certificate": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "private_key": String::from_utf8_lossy(&cert_bundle.private_key.private_key_to_pem_pkcs8()?),
            "private_key_type": cert_bundle.private_key_type.clone(),
            "serial_number": cert_bundle.serial_number.clone(),
        })
        .as_object()
        .unwrap()
        .clone();

        if role_entry.generate_lease {
            let mut secret_data: Map<String, Value> = Map::new();
            secret_data.insert("serial_number".to_string(), Value::String(cert_bundle.serial_number.clone()));

            let mut resp = backend.secret("pki").unwrap().response(Some(resp_data), Some(secret_data));
            let secret = resp.secret.as_mut().unwrap();

            let now_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?;

            secret.lease.ttl = Duration::from_secs(cert_expiration as u64) - now_timestamp;
            secret.lease.renewable = true;

            return Ok(Some(resp));
        } else {
            return Ok(Some(Response::data_response(Some(resp_data))));
        }
    }

    pub fn fetch_cert(&self, req: &Request) -> Result<CertBundle, RvError> {
        let serial_number_value = req.get_data("serial")?;
        let serial_number = serial_number_value.as_str().unwrap();
        let serial_number_hex = serial_number.replace(":", "-").to_lowercase();
        let entry = req.storage_get(format!("certs/{}", serial_number_hex).as_str())?;
        if entry.is_none() {
            return Err(RvError::ErrPkiCertNotFound);
        }

        let cert_bundle: CertBundle = serde_json::from_slice(entry.unwrap().value.as_slice())?;
        Ok(cert_bundle)
    }
}
