use serde_json::json;
use crate::{
    logical::{
        Backend, Request, Response,
    },
    utils::cert::CertBundle,
    errors::RvError,
};
use super::{
    PkiBackendInner,
};

impl PkiBackendInner {
    pub fn handle_fetch_cert_bundle(&self, cert_bundle: &CertBundle) -> Result<Option<Response>, RvError> {
        let ca_chain_pem: String = cert_bundle.ca_chain.iter()
            .map(|x509| x509.to_pem().unwrap())
            .map(|pem| String::from_utf8_lossy(&pem).to_string())
            .collect::<Vec<String>>()
            .join("");
        let resp_data = json!({
            "ca_chain": ca_chain_pem,
            "certificate": String::from_utf8_lossy(&cert_bundle.certificate.to_pem()?),
            "serial_number": cert_bundle.serial_number.clone(),
        }).as_object().unwrap().clone();

        Ok(Some(Response::data_response(Some(resp_data))))
    }

    pub fn read_path_fetch_ca(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let ca_bundle = self.fetch_ca_info(req)?;
        self.handle_fetch_cert_bundle(&ca_bundle)
    }

    pub fn read_path_fetch_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }

    pub fn read_path_fetch_cert(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let cert_bundle = self.fetch_cert(req)?;
        self.handle_fetch_cert_bundle(&cert_bundle)
    }

    pub fn read_path_fetch_cert_crl(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        Ok(None)
    }
}

