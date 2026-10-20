//! The sealed metadata credential bundle (RFC 8439 ChaCha20-Poly1305).
//!
//! Port of `ciplink/_logix_bundle_codec.py` and `ciplink/_logix_metadata_bundle.py`. The key is embedded next
//! to the bundle, so this is obfuscation, not secrecy. Never log what [`open_credentials`] returns.
//!
//! Bundle layout: `b"LMK1"`, a 12-byte nonce, then the sealed payload (the header is the associated data).
//! The payload is the certificate length and key length (UINT each), the certificate and the DER key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::auth::LogixMetadataCredentials;
use crate::{Error, Result};

include!("bundle_data.rs");

const HEADER: &[u8; 4] = b"LMK1";

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// Seals a certificate and DER private key with `key` and a random nonce.
pub fn seal_credentials(certificate: &[u8], private_key: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if !matches!(certificate.len(), 281 | 285) || !(1..=2048).contains(&private_key.len()) {
        return Err(Error::request("Unsupported credential bundle lengths"));
    }
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| Error::request("Could not generate a bundle nonce"))?;
    let mut payload = Vec::with_capacity(4 + certificate.len() + private_key.len());
    // both lengths were checked to fit a UINT above
    payload.extend_from_slice(&(certificate.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(private_key.len() as u16).to_le_bytes());
    payload.extend_from_slice(certificate);
    payload.extend_from_slice(private_key);
    let sealed = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: HEADER,
            },
        )
        .map_err(|_| Error::request("Could not seal the credential bundle"))?;
    let mut out = Vec::with_capacity(16 + sealed.len());
    out.extend_from_slice(HEADER);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a sealed bundle with `key`; returns (certificate, DER private key).
pub fn open_credentials(bundle: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    if !(36..=4096).contains(&bundle.len()) || &bundle[..4] != HEADER {
        return Err(Error::request("Unsupported encrypted credential bundle"));
    }
    let payload = cipher(key)
        .decrypt(
            Nonce::from_slice(&bundle[4..16]),
            Payload {
                msg: &bundle[16..],
                aad: HEADER,
            },
        )
        .map_err(|_| Error::request("Credential bundle authentication failed"))?;
    if payload.len() < 4 {
        return Err(Error::request("Truncated credential bundle payload"));
    }
    let certificate_size = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    let key_size = usize::from(u16::from_le_bytes([payload[2], payload[3]]));
    if !matches!(certificate_size, 281 | 285) || !(1..=2048).contains(&key_size) {
        return Err(Error::request(
            "Unsupported credential bundle payload lengths",
        ));
    }
    if payload.len() != 4 + certificate_size + key_size {
        return Err(Error::request("Credential bundle payload length mismatch"));
    }
    let certificate = payload[4..4 + certificate_size].to_vec();
    let private_key = payload[4 + certificate_size..].to_vec();
    Ok((certificate, private_key))
}

/// Opens the bundle embedded in this library; returns (certificate, DER private key).
pub fn load_bundled() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = SHARES[0][i] ^ SHARES[1][i] ^ SHARES[2][i];
    }
    open_credentials(&SEALED, &key)
}

/// The credentials embedded in this library.
pub fn bundled_credentials() -> Result<LogixMetadataCredentials> {
    let (certificate, private_key) = load_bundled()?;
    LogixMetadataCredentials::new(&certificate, &private_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aead_matches_rfc8439_section_2_8_2() {
        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
        let nonce = unhex("070000004041424344454647");
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = unhex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ));
        let sealed = cipher(&key)
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(sealed, expected);
    }

    #[test]
    fn embedded_bundle_opens() {
        let (certificate, private_key) = load_bundled().unwrap();
        assert!(matches!(certificate.len(), 281 | 285));
        assert!(!private_key.is_empty());
    }
}
