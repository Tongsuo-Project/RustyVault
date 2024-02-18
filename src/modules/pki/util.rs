use std::time::{Duration, SystemTime};

use humantime::{parse_duration, parse_rfc3339};
use openssl::x509::X509NameBuilder;

use super::path_roles::RoleEntry;
use crate::{errors::RvError, logical::Request, utils::cert::Certificate};

pub fn get_role_params(req: &mut Request) -> Result<RoleEntry, RvError> {
    let ttl_vale = req.get_data("ttl")?;
    let ttl = {
        let ttl_str = ttl_vale.as_str().unwrap();
        parse_duration(ttl_str)?
    };
    let not_before_duration_vale = req.get_data("not_before_duration")?;
    let not_before_duration = Duration::from_secs(not_before_duration_vale.as_u64().unwrap());
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
    let use_pss_value = req.get_data("use_pss")?;
    let use_pss = use_pss_value.as_bool().unwrap();
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
    let not_after_vale = req.get_data("not_after")?;
    let not_after = not_after_vale.as_str().unwrap().to_string();

    let role_entry = RoleEntry {
        ttl,
        not_before_duration,
        use_pss,
        key_type: key_type.to_string(),
        key_bits: key_bits as u32,
        signature_bits: signature_bits as u32,
        country,
        province,
        locality,
        organization,
        ou,
        street_address,
        postal_code,
        not_after,
        ..Default::default()
    };

    Ok(role_entry)
}

pub fn generate_certificate(role_entry: &RoleEntry, req: &mut Request) -> Result<Certificate, RvError> {
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

    let not_before = SystemTime::now() - Duration::from_secs(10);
    let not_after: SystemTime;
    if role_entry.not_after.len() > 18 {
        let parsed_time = parse_rfc3339(&role_entry.not_after)?;
        not_after = parsed_time.into();
    } else {
        if role_entry.ttl != Duration::from_secs(0) {
            not_after = not_before + role_entry.ttl;
        } else {
            not_after = not_before + role_entry.max_ttl;
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

    let cert = Certificate {
        not_before,
        not_after,
        subject,
        dns_sans: common_names,
        ip_sans,
        key_bits: role_entry.key_bits,
        ..Default::default()
    };

    Ok(cert)
}
