//! TLS for S7comm-plus (spec 4): a rustls client config for TLS 1.3 with AES-GCM, and a certificate verifier
//! that checks no chain and no name (the PLC certificate is self-signed and names the project IP) but records
//! the certificate's SHA-256 fingerprint and refuses it when a pin is set and differs. The handshake signature
//! is still verified with the presented key, so a pin proves possession of the pinned key.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring as provider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::{Error, Result};

/// A SHA-256 certificate fingerprint.
pub type Fingerprint = [u8; 32];

/// The fingerprint of the latest handshake, shared between the verifier and the driver.
pub type SeenFingerprint = Arc<Mutex<Option<Fingerprint>>>;

/// SHA-256 of a DER certificate.
pub fn fingerprint(der: &[u8]) -> Fingerprint {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// `AB:CD:...`: 32 upper-case hex pairs joined by `:` (what `openssl x509 -fingerprint -sha256` prints).
pub fn format_fingerprint(fp: &Fingerprint) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parses a pin: 64 hex digits, upper or lower case, with or without `:` or spaces.
pub fn parse_fingerprint(text: &str) -> Result<Fingerprint> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b':' | b' ' | b'-'))
        .collect();
    let bad = || {
        Error::request(format!(
            "tls_fingerprint must be 32 hex bytes (SHA-256), got {text:?}"
        ))
    };
    if digits.len() != 64 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).map_err(|_| bad())?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Records the certificate's fingerprint; refuses it when a pin is set and differs.
#[derive(Debug)]
struct PinVerifier {
    pin: Option<Fingerprint>,
    seen: SeenFingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

/// The rustls error message of a pin mismatch (the link turns it into the driver's message).
pub const PIN_MISMATCH: &str = "certificate fingerprint does not match the pin";

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(fp);
        match self.pin {
            Some(pin) if pin != fp => Err(rustls::Error::General(PIN_MISMATCH.into())),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // the config allows TLS 1.3 only
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The client config of one connect: TLS 1.3 only, AES-256-GCM and AES-128-GCM, no resumption, no SNI.
pub fn client_config(pin: Option<Fingerprint>, seen: SeenFingerprint) -> Result<Arc<ClientConfig>> {
    let mut crypto = provider::default_provider();
    crypto.cipher_suites = vec![
        provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    let algorithms = crypto.signature_verification_algorithms;
    let verifier = PinVerifier {
        pin,
        seen,
        algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::comm(format!("TLS setup failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_sni = false;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_format_as_upper_case_pairs() {
        let mut fp = [0u8; 32];
        fp[0] = 0xAB;
        fp[31] = 0x0C;
        let text = format_fingerprint(&fp);
        assert_eq!(text.len(), 95);
        assert!(text.starts_with("AB:00:"));
        assert!(text.ends_with(":0C"));
        assert_eq!(parse_fingerprint(&text).expect("parse"), fp);
    }

    #[test]
    fn pins_parse_in_any_case_and_with_any_separator() {
        let upper = "AB".repeat(32);
        let want = [0xAB; 32];
        assert_eq!(parse_fingerprint(&upper).expect("plain"), want);
        assert_eq!(
            parse_fingerprint(&upper.to_lowercase()).expect("lower"),
            want
        );
        let spaced = vec!["ab"; 32].join(" ");
        assert_eq!(parse_fingerprint(&spaced).expect("spaces"), want);
        let colons = vec!["Ab"; 32].join(":");
        assert_eq!(parse_fingerprint(&colons).expect("colons"), want);
    }

    #[test]
    fn malformed_pins_are_request_errors() {
        for bad in [
            "",
            "AB",
            &"AB".repeat(31),
            &"AB".repeat(33),
            &"ZZ".repeat(32),
        ] {
            assert!(
                matches!(parse_fingerprint(bad), Err(Error::Request { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn sha256_of_known_input() {
        assert_eq!(
            format_fingerprint(&fingerprint(b"abc")),
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
        );
    }

    #[test]
    fn the_client_config_builds() {
        let config = client_config(None, Arc::default()).expect("config");
        assert!(!config.enable_sni);
    }
}
