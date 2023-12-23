use std::sync::Arc;

use rcgen::CertificateParams;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};

pub static ROOT_CERT: std::sync::OnceLock<rcgen::Certificate> = std::sync::OnceLock::new();
pub fn root_cert() -> &'static rcgen::Certificate {
    ROOT_CERT.get_or_init(|| {
        let mut param = rcgen::CertificateParams::default();

        param.distinguished_name = rcgen::DistinguishedName::new();
        param.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("<HANERU CA>".to_string()),
        );
        param.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        param.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rcgen::Certificate::from_params(param).unwrap()
    })
}

pub fn server_config(host: String) -> Arc<ServerConfig> {
    let mut cert_params = CertificateParams::new(vec![host.into()]);
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

    let cert = rcgen::Certificate::from_params(cert_params).unwrap();
    let signed = cert.serialize_der_with_signer(root_cert()).unwrap();
    let private_key = cert.get_key_pair().serialize_der();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(signed)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
        )
        .unwrap();
    Arc::new(server_config)
}

pub fn server_config21(host: String) -> Arc<rustls21::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![host]).unwrap();
    let private_key = cert.get_key_pair().serialize_der();

    let signed = cert.serialize_der_with_signer(root_cert()).unwrap();
    let mut server_config = rustls21::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls21::Certificate(signed)],
            rustls21::PrivateKey(private_key),
        )
        .unwrap();

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(server_config)
}
