use std::vec::Vec;

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_name;
use rustls::server::ParsedCertificate;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::{Error, SignatureScheme};
use rustls_platform_verifier::ConfigVerifierExt;
use std::sync::Arc;
use tracing::trace;

#[derive(Debug)]
pub struct SelfSignedPkiVerifier {
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

#[allow(unreachable_pub)]
impl SelfSignedPkiVerifier {
    pub fn new(verifier: Arc<rustls::client::WebPkiServerVerifier>) -> Self {
        SelfSignedPkiVerifier { verifier }
    }
}

impl ServerCertVerifier for SelfSignedPkiVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Not Expired
    /// - Valid for DNS entry
    /// - Valid revocation status (if applicable).
    ///
    /// Depending on the verifier's configuration revocation status checking may be performed for
    /// each certificate in the chain to a root CA (excluding the root itself), or only the
    /// end entity certificate. Similarly, unknown revocation status may be treated as an error
    /// or allowed based on configuration.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

pub fn crypto_client_init(
    c: &crate::config::client::CryptoConfig,
) -> crate::Result<Arc<rustls::ClientConfig>> {
    let crypto_cfg = crate::config::client::Crypto::from_config(c)?;
    let config: Arc<_> = if c.ca.is_some() {
        let mut root_cert_store = rustls::RootCertStore::empty();

        for cert in crypto_cfg.ca {
            root_cert_store.add(cert).unwrap();
        }

        rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
            .into()
    } else if c.allow_self_signed {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let b = rustls::client::WebPkiServerVerifier::builder(root_cert_store.into()).build()?;
        let verifier = SelfSignedPkiVerifier::new(b);
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
            .into()
    } else {
        ClientConfig::with_platform_verifier().into()
    };

    Ok(config)
}
