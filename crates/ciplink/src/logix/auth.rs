//! Logix metadata authentication: the signed public credential, its RSA private key and the challenge proof.
//!
//! Port of `ciplink/logix_auth.py`. The observed protocol uses raw, little-endian 1024-bit RSA and SHA-1; it
//! is not TLS, CIP Security or general-purpose RSA. A `ValueError` there is [`Error::Request`] here.

use std::fmt;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha1::{Digest, Sha1};

use crate::{Error, Result};

const KEY_HEADER: [u8; 13] = [
    0x02, 0x00, 0x80, 0x80, 0x03, 0x00, 0x01, 0x00, 0x01, 0x81, 0x80, 0x80, 0x00,
];
const RSA_ALGORITHM: [u8; 13] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// The claim (identifier, level) that grants metadata access.
const METADATA_CLAIM: (u16, u16) = (11, 1);

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

/// Validates the two observed public credential layouts (281 or 285 bytes), not their signature (the
/// controller checks that), and returns the claims as (identifier, level).
pub fn validate_metadata_certificate(certificate: &[u8]) -> Result<Vec<(u16, u16)>> {
    if !matches!(certificate.len(), 281 | 285) {
        return Err(Error::request(
            "Expected an observed 281- or 285-byte public certificate",
        ));
    }
    let word = |at| u16_at(certificate, at).unwrap_or_default(); // in range: the length is 281 or 285
    let (size, version, issuer, count) = (word(0), word(2), word(4), word(6));
    if usize::from(size) + 128 != certificate.len()
        || version != 1
        || issuer != 1
        || !(1..=2).contains(&count)
    {
        return Err(Error::request("Unsupported public certificate header"));
    }
    let claims: Vec<(u16, u16)> = (0..usize::from(count))
        .map(|i| (word(8 + 4 * i), word(10 + 4 * i)))
        .collect();
    if claims.iter().any(|&(_, level)| level != 1) {
        return Err(Error::request("Unsupported certificate claim layout"));
    }
    let key_start = 8 + 4 * claims.len();
    if certificate.get(key_start..key_start + 13) != Some(&KEY_HEADER[..]) {
        return Err(Error::request("Unsupported certificate public-key layout"));
    }
    if key_start + 13 + 128 != usize::from(size) {
        return Err(Error::request("Certificate public-key length mismatch"));
    }
    Ok(claims)
}

/// A strict, bounded DER reader for a plain RSA private key only.
struct DerReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        DerReader { data, position: 0 }
    }

    fn at_end(&self) -> bool {
        self.position >= self.data.len()
    }

    fn item(&mut self, tag: u8) -> Result<&'a [u8]> {
        let data = self.data;
        let mut position = self.position;
        if position + 2 > data.len() || data[position] != tag {
            return Err(Error::request("Invalid RSA private-key DER structure"));
        }
        let mut length = usize::from(data[position + 1]);
        position += 2;
        if length & 0x80 != 0 {
            let count = length & 0x7F;
            if !(1..=2).contains(&count) || position + count > data.len() {
                return Err(Error::request("Invalid RSA private-key DER length"));
            }
            let encoded = &data[position..position + count];
            if encoded[0] == 0 {
                return Err(Error::request("Noncanonical RSA private-key DER length"));
            }
            length = encoded.iter().fold(0, |n, &b| (n << 8) | usize::from(b));
            if length < 128 {
                return Err(Error::request("Noncanonical RSA private-key DER length"));
            }
            position += count;
        }
        let end = position + length;
        if end > data.len() {
            return Err(Error::request("Truncated RSA private-key DER"));
        }
        self.position = end;
        Ok(&data[position..end])
    }

    fn integer(&mut self) -> Result<BigUint> {
        let encoded = self.item(2)?;
        match encoded {
            [] => Err(Error::request("RSA key integers must be nonnegative")),
            [first, ..] if first & 0x80 != 0 => {
                Err(Error::request("RSA key integers must be nonnegative"))
            }
            [0, second, ..] if second & 0x80 == 0 => {
                Err(Error::request("Noncanonical RSA key integer"))
            }
            _ => Ok(BigUint::from_bytes_be(encoded)),
        }
    }
}

fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut a, mut b) = (a.clone(), b.clone());
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

/// Parses an unencrypted PKCS #1 or PKCS #8 two-prime RSA key and checks it; returns (n, e, d).
fn private_numbers(data: &[u8]) -> Result<(BigUint, BigUint, BigUint)> {
    if !(1..=2048).contains(&data.len()) {
        return Err(Error::request(
            "Supply an unencrypted PKCS #1 or PKCS #8 RSA private key in DER format",
        ));
    }
    let mut outer = DerReader::new(data);
    let mut inner = DerReader::new(outer.item(0x30)?);
    if outer.position != data.len() {
        return Err(Error::request("Unexpected data after RSA private key"));
    }
    let mut version = inner.integer()?;
    if !inner.at_end() && inner.data[inner.position] == 0x30 {
        // PKCS #8 PrivateKeyInfo wraps the PKCS #1 key in an OCTET STRING.
        if !version.is_zero() || inner.item(0x30)? != RSA_ALGORITHM {
            return Err(Error::request(
                "Unsupported PKCS #8 RSA algorithm or version",
            ));
        }
        let wrapped = inner.item(4)?;
        if !inner.at_end() {
            return Err(Error::request("Unexpected PKCS #8 private-key fields"));
        }
        let mut wrapper = DerReader::new(wrapped);
        inner = DerReader::new(wrapper.item(0x30)?);
        if wrapper.position != wrapped.len() {
            return Err(Error::request("Unexpected data after PKCS #8 RSA key"));
        }
        version = inner.integer()?;
    }
    let mut numbers = Vec::with_capacity(8);
    for _ in 0..8 {
        numbers.push(inner.integer()?);
    }
    if !inner.at_end() || !version.is_zero() {
        return Err(Error::request(
            "Only a two-prime PKCS #1 RSA private key is supported",
        ));
    }
    let [n, e, d, p, q, dp, dq, coefficient]: [BigUint; 8] = numbers
        .try_into()
        .map_err(|_| Error::request("Invalid RSA private-key DER structure"))?;
    let one = BigUint::one();
    let two = BigUint::from(2u8);
    if n.bits() != 1024
        || e != BigUint::from(65537u32)
        || !(one < d && d < n)
        || p <= two
        || q <= two
        || p == q
    {
        return Err(Error::request("Unsupported RSA private-key parameters"));
    }
    if &p * &q != n {
        return Err(Error::request("Inconsistent RSA private-key modulus"));
    }
    let (p1, q1) = (&p - &one, &q - &one);
    let order = &p1 * &q1 / gcd(&p1, &q1);
    if (&e * &d) % &order != one
        || dp != &d % &p1
        || dq != &d % &q1
        || (&coefficient * &q) % &p != one
    {
        return Err(Error::request("Inconsistent RSA private-key components"));
    }
    Ok((n, e, d))
}

/// A signed metadata credential and its matching RSA private key.
///
/// Keep keys out of logs: `Debug` prints no key material. RSA blinding is used because big-integer arithmetic
/// is not constant-time.
#[derive(Clone)]
pub struct LogixMetadataCredentials {
    certificate: Vec<u8>,
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

impl fmt::Debug for LogixMetadataCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogixMetadataCredentials(<redacted>)")
    }
}

impl LogixMetadataCredentials {
    /// Credentials from a public certificate carrying the metadata claim and its unencrypted PKCS #1 or
    /// PKCS #8 DER private key.
    pub fn new(certificate: &[u8], private_key_der: &[u8]) -> Result<Self> {
        let claims = validate_metadata_certificate(certificate)?;
        if !claims.contains(&METADATA_CLAIM) {
            return Err(Error::request(
                "Certificate lacks the observed metadata access claim",
            ));
        }
        let (n, e, d) = private_numbers(private_key_der)?;
        let key_start = 8 + 4 * claims.len();
        let public = BigUint::from_bytes_be(&certificate[key_start + 13..key_start + 141]);
        if n != public {
            return Err(Error::request(
                "Private key does not match the signed certificate",
            ));
        }
        Ok(LogixMetadataCredentials {
            certificate: certificate.to_vec(),
            n,
            e,
            d,
        })
    }

    /// The credentials sealed into this library (see [`crate::logix::bundle`]).
    pub fn bundled() -> Result<Self> {
        super::bundle::bundled_credentials()
    }

    /// The public certificate sent to the controller.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The 20-byte proof for the payload of a successful service 0x4B reply: a length-prefixed (0x0080),
    /// little-endian 128-byte RSA ciphertext.
    pub fn answer_challenge(&self, data: &[u8]) -> Result<[u8; 20]> {
        if data.len() != 130 || data[..2] != [0x80, 0x00] {
            return Err(Error::request(
                "Expected a length-prefixed 128-byte metadata challenge",
            ));
        }
        let ciphertext = BigUint::from_bytes_le(&data[2..]);
        if ciphertext >= self.n {
            return Err(Error::request(
                "Metadata challenge is outside the RSA modulus",
            ));
        }
        let (factor, inverse) = self.blinding_factor()?;
        let blinded = &ciphertext * factor.modpow(&self.e, &self.n) % &self.n;
        let plain = blinded.modpow(&self.d, &self.n) * inverse % &self.n;
        if plain.modpow(&self.e, &self.n) != ciphertext {
            return Err(Error::request(
                "RSA challenge calculation failed verification",
            ));
        }
        let mut bytes = plain.to_bytes_le();
        bytes.resize(128, 0);
        Ok(Sha1::digest(&bytes[..20]).into())
    }

    /// A random factor in 2..=n-2 that is invertible modulo n, and its inverse.
    fn blinding_factor(&self) -> Result<(BigUint, BigUint)> {
        let fail = || Error::request("Could not generate an RSA blinding factor");
        let span = &self.n - 3u8;
        for _ in 0..128 {
            // 64 extra bits make the bias of the reduction negligible.
            let mut random = [0u8; 136];
            getrandom::fill(&mut random).map_err(|_| fail())?;
            let factor = BigUint::from_bytes_le(&random) % &span + 2u8;
            if let Some(inverse) = factor.modinv(&self.n) {
                return Ok((factor, inverse));
            }
        }
        Err(fail())
    }

    /// Checks the controller's granted-claims reply: a count, then (claim UINT, level UDINT) pairs, unique,
    /// including the metadata claim.
    pub fn validate_completion(&self, data: &[u8]) -> Result<()> {
        let Some(count) = u16_at(data, 0) else {
            return Err(Error::request("Missing metadata authentication grants"));
        };
        let count = usize::from(count);
        if !(1..=64).contains(&count) || data.len() != 2 + count * 6 {
            return Err(Error::request("Malformed metadata authentication grants"));
        }
        let grants: Vec<(u16, u32)> = data[2..]
            .chunks_exact(6)
            .map(|g| {
                (
                    u16::from_le_bytes([g[0], g[1]]),
                    u32::from_le_bytes([g[2], g[3], g[4], g[5]]),
                )
            })
            .collect();
        let mut claims: Vec<u16> = grants.iter().map(|g| g.0).collect();
        claims.sort_unstable();
        claims.dedup();
        if claims.len() != count {
            return Err(Error::request("Duplicate metadata authentication grant"));
        }
        if !grants.contains(&(METADATA_CLAIM.0, u32::from(METADATA_CLAIM.1))) {
            return Err(Error::request("Controller did not grant metadata access"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn der_rejects_negative_empty_and_noncanonical_integers() {
        for data in [&b"\x02\x01\x80"[..], b"\x02\x02\x00\x01", b"\x02\x00"] {
            assert!(DerReader::new(data).integer().is_err(), "{data:?}");
        }
        assert_eq!(
            DerReader::new(b"\x02\x02\x00\x80").integer().unwrap(),
            BigUint::from(128u8)
        );
    }

    #[test]
    fn der_long_lengths_must_be_canonical() {
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0u8; 128]);
        assert_eq!(DerReader::new(&long).item(4).unwrap().len(), 128);
        assert!(DerReader::new(b"\x04\x81\x7f").item(4).is_err());
        assert!(DerReader::new(b"\x04\x82\x00\x80").item(4).is_err());
        assert!(DerReader::new(b"\x04\x83\x00\x00\x01").item(4).is_err());
    }

    #[test]
    fn gcd_matches_euclid() {
        assert_eq!(
            gcd(&BigUint::from(12u8), &BigUint::from(18u8)),
            BigUint::from(6u8)
        );
    }
}
