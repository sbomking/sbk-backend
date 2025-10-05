use axum::body::Body;
use hyper::{header::USER_AGENT, http::HeaderValue};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::{Client, connect::HttpConnector}, rt::TokioExecutor};
use tower::ServiceBuilder;
use tower_http::{trace::TraceLayer, classify::{StatusInRangeAsFailures, SharedClassifier}, set_header::{SetRequestHeaderLayer, SetRequestHeader}, decompression::{DecompressionLayer, Decompression}};

use crate::error::ErrorMsg;


#[derive(Debug)]
pub struct NoCertificateVerification {}
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
 
     fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let mut sign = vec![];
        sign.push(rustls::SignatureScheme::ECDSA_NISTP256_SHA256);
        sign.push(rustls::SignatureScheme::ECDSA_NISTP384_SHA384);
        sign.push(rustls::SignatureScheme::ECDSA_NISTP521_SHA512);
        sign.push(rustls::SignatureScheme::ED25519);
        sign.push(rustls::SignatureScheme::ED448);
        sign.push(rustls::SignatureScheme::RSA_PKCS1_SHA1);
        sign.push(rustls::SignatureScheme::RSA_PKCS1_SHA256);
        sign.push(rustls::SignatureScheme::RSA_PKCS1_SHA384);
        sign.push(rustls::SignatureScheme::RSA_PKCS1_SHA512);
        sign.push(rustls::SignatureScheme::RSA_PSS_SHA256);
        sign.push(rustls::SignatureScheme::RSA_PSS_SHA384);
        sign.push(rustls::SignatureScheme::RSA_PSS_SHA512);
        sign
    }
}


pub fn get_rustls_config_dangerous() -> Result<rustls::ClientConfig, hyper::Error> {
    let store = rustls::RootCertStore::empty();
    
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();

    // if you want to completely disable cert-verification, use this
    let mut dangerous_config = rustls::ClientConfig::dangerous(&mut config);
    dangerous_config.set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification {}));

    Ok(config)
}

pub async fn get_hyper_client_unsecure() -> Result<tower_http::trace::Trace<SetRequestHeader<Decompression<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Body>>, HeaderValue>, SharedClassifier<StatusInRangeAsFailures>>, ErrorMsg> {

    let _ = rustls::crypto::ring::default_provider().install_default();
    
    let https_unsecure = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(get_rustls_config_dangerous()?)
        .https_only()
        .enable_http2()
        .build();

    let hyper_client :Client<HttpsConnector<HttpConnector>, Body> = 
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(https_unsecure);

    //https://docs.rs/tower-http/latest/tower_http/
    let client = ServiceBuilder::new()
        .layer(TraceLayer::new(StatusInRangeAsFailures::new(400..=599).into_make_classifier()))
        .layer(SetRequestHeaderLayer::overriding(USER_AGENT,HeaderValue::from_static("tower-http demo")))
        .layer(DecompressionLayer::new())
        .service(hyper_client);

    Ok(client)
}

pub fn get_hyper_client() -> Result<tower_http::trace::Trace<SetRequestHeader<Decompression<hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Body>>, HeaderValue>, SharedClassifier<StatusInRangeAsFailures>>, ErrorMsg> {

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_mozilla = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let https_mozilla = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_mozilla)
        .https_only()
        .enable_http2()
        .build();

    let hyper_client :Client<HttpsConnector<HttpConnector>, Body> = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https_mozilla);

    let client = ServiceBuilder::new()
        .layer(TraceLayer::new(StatusInRangeAsFailures::new(400..=599).into_make_classifier()))
        .layer(SetRequestHeaderLayer::overriding(USER_AGENT,HeaderValue::from_static("tower-http demo")))
        .layer(DecompressionLayer::new())
        .service(hyper_client);

    Ok(client)
}
