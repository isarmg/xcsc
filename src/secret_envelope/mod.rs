//! A single current envelope with explicit product domain and caller-provided object binding.

use crate::secret::{SecretBytes, SecretKey};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"SGEV";
pub const NONCE_BYTES: usize = 12;
pub const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_BINDING_BYTES: usize = 4096;

pub const MAX_DOMAIN_BYTES: usize = u16::MAX as usize;
pub const HEADER_BYTES: usize = MAGIC.len() + size_of::<u16>();
pub const TAG_BYTES: usize = 16;
pub const MASTER_KEY_BYTES: usize = 32;
pub const CURRENT_ENVELOPE_VALIDATION_VECTORS_JSON: &str =
    include_str!("fixtures/current-envelope-v1.json");

pub trait EnvelopeDomain {
    const DOMAIN: &'static [u8];
    const REVISION: u16;
}

pub fn seal<D: EnvelopeDomain>(
    master: &SecretKey<MASTER_KEY_BYTES>,
    binding: &[u8],
    plaintext: &SecretBytes,
) -> Result<Vec<u8>, Error> {
    seal_with_domain(master, D::DOMAIN, D::REVISION, binding, plaintext)
}

/// Seal the one current envelope using a verified caller-owned domain policy.
pub fn seal_with_domain(
    master: &SecretKey<MASTER_KEY_BYTES>,
    domain: &[u8],
    revision: u16,
    binding: &[u8],
    plaintext: &SecretBytes,
) -> Result<Vec<u8>, Error> {
    validate_domain_binding(domain, binding)?;
    if plaintext.expose().len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::PlaintextTooLarge);
    }
    let key = derive_key(master, domain, binding)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let aad = aad(domain, revision, binding)?;
    let ciphertext = cipher
        .encrypt(
            <&Nonce<aes_gcm::aead::consts::U12>>::try_from(&nonce[..])
                .map_err(|_| Error::Crypto)?,
            Payload {
                msg: plaintext.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut output = Vec::with_capacity(HEADER_BYTES + NONCE_BYTES + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&revision.to_be_bytes());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn open<D: EnvelopeDomain>(
    master: &SecretKey<MASTER_KEY_BYTES>,
    binding: &[u8],
    envelope: &[u8],
) -> Result<SecretBytes, Error> {
    open_with_domain(master, D::DOMAIN, D::REVISION, binding, envelope)
}

/// Verify the exact current domain/revision obtained from trusted contract
/// data. Never infer the expected policy from the untrusted envelope header.
pub fn open_with_domain(
    master: &SecretKey<MASTER_KEY_BYTES>,
    domain: &[u8],
    revision: u16,
    binding: &[u8],
    envelope: &[u8],
) -> Result<SecretBytes, Error> {
    validate_domain_binding(domain, binding)?;
    if envelope.len() < HEADER_BYTES + NONCE_BYTES + TAG_BYTES
        || envelope.len() > HEADER_BYTES + NONCE_BYTES + TAG_BYTES + MAX_PLAINTEXT_BYTES
    {
        return Err(Error::Malformed);
    }
    if &envelope[..4] != MAGIC || u16::from_be_bytes([envelope[4], envelope[5]]) != revision {
        return Err(Error::WrongRevision);
    }
    let key = derive_key(master, domain, binding)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto)?;
    let aad = aad(domain, revision, binding)?;
    let plaintext = cipher
        .decrypt(
            <&Nonce<aes_gcm::aead::consts::U12>>::try_from(
                &envelope[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES],
            )
            .map_err(|_| Error::Malformed)?,
            Payload {
                msg: &envelope[HEADER_BYTES + NONCE_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(SecretBytes::new(plaintext))
}

fn validate_domain_binding(domain: &[u8], binding: &[u8]) -> Result<(), Error> {
    if domain.is_empty() || binding.is_empty() {
        return Err(Error::MissingDomainBinding);
    }
    if domain.len() > MAX_DOMAIN_BYTES {
        return Err(Error::DomainTooLarge);
    }
    if binding.len() > MAX_BINDING_BYTES {
        return Err(Error::BindingTooLarge);
    }
    Ok(())
}

fn derive_key(
    master: &SecretKey<MASTER_KEY_BYTES>,
    domain: &[u8],
    binding: &[u8],
) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>, Error> {
    let hk = Hkdf::<Sha256>::new(Some(domain), master.expose());
    let mut key = Zeroizing::new([0_u8; MASTER_KEY_BYTES]);
    hk.expand(binding, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}
fn aad(domain: &[u8], revision: u16, binding: &[u8]) -> Result<Vec<u8>, Error> {
    let domain_len = u16::try_from(domain.len()).map_err(|_| Error::MissingDomainBinding)?;
    let binding_len = u32::try_from(binding.len()).map_err(|_| Error::MissingDomainBinding)?;
    let mut aad = Vec::with_capacity(8 + domain.len() + binding.len());
    aad.extend_from_slice(&domain_len.to_be_bytes());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&binding_len.to_be_bytes());
    aad.extend_from_slice(binding);
    Ok(aad)
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    #[error("envelope requires a non-empty domain and binding")]
    MissingDomainBinding,
    #[error("plaintext exceeds the envelope budget")]
    PlaintextTooLarge,
    #[error("object binding exceeds the envelope budget")]
    BindingTooLarge,
    #[error("envelope domain exceeds its byte budget")]
    DomainTooLarge,
    #[error("malformed envelope")]
    Malformed,
    #[error("envelope revision does not match the current domain revision")]
    WrongRevision,
    #[error("envelope authentication failed")]
    Authentication,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("secure randomness unavailable")]
    Randomness,
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Test;
    impl EnvelopeDomain for Test {
        const DOMAIN: &'static [u8] = b"test/credential";
        const REVISION: u16 = 1;
    }
    #[test]
    fn independent_hkdf_aes_gcm_vector_preserves_current_envelope_bytes() {
        // Independently generated with Python cryptography HKDF-SHA256 and
        // AESGCM (fixed test-only master/nonce), not this crate's seal function.
        let master = SecretKey::new([9; 32]);
        let expected_key = [
            0x1a, 0xd2, 0x78, 0x0b, 0x8e, 0xa1, 0xdf, 0xfd, 0xe4, 0xed, 0xad, 0x0c, 0x5c, 0x75,
            0x6e, 0x09, 0x48, 0x92, 0x34, 0x79, 0xc6, 0xd9, 0xbe, 0xab, 0x0b, 0xe5, 0x7d, 0xee,
            0xa8, 0x6f, 0x67, 0xeb,
        ];
        assert_eq!(
            &derive_key(&master, Test::DOMAIN, b"object-1").unwrap()[..],
            &expected_key
        );
        let envelope = [
            0x53, 0x47, 0x45, 0x56, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x9b, 0x37, 0xbc, 0xe1, 0x9c, 0xdb, 0x9c, 0x13, 0xcc, 0x3e,
            0x16, 0xb2, 0x67, 0x3c, 0xea, 0x12, 0xaf, 0x36, 0x82, 0x04, 0xf8, 0x4d,
        ];
        assert_eq!(
            open::<Test>(&master, b"object-1", &envelope)
                .unwrap()
                .expose(),
            b"secret"
        );
        assert_eq!(
            open::<Test>(&master, b"object-2", &envelope).unwrap_err(),
            Error::Authentication
        );
        let cipher = Aes256Gcm::new_from_slice(&expected_key).unwrap();
        let aad = aad(Test::DOMAIN, Test::REVISION, b"object-1").unwrap();
        let actual = cipher
            .encrypt(
                <&Nonce<aes_gcm::aead::consts::U12>>::try_from(
                    &envelope[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES],
                )
                .unwrap(),
                Payload {
                    msg: b"secret",
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&actual, &envelope[HEADER_BYTES + NONCE_BYTES..]);
    }
    fn fixture_bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
        let hex = value[field].as_str().unwrap();
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn public_vectors_verify_actual_kdf_aad_and_current_format() {
        let vector: serde_json::Value =
            serde_json::from_str(CURRENT_ENVELOPE_VALIDATION_VECTORS_JSON).unwrap();
        let master = SecretKey::new(fixture_bytes(&vector, "master_hex").try_into().unwrap());
        let domain = fixture_bytes(&vector, "domain_hex");
        let binding = fixture_bytes(&vector, "binding_hex");
        let envelope = fixture_bytes(&vector, "envelope_hex");
        let revision = u16::try_from(vector["revision"].as_u64().unwrap()).unwrap();
        assert_eq!(
            derive_key(&master, &domain, &binding).unwrap().as_slice(),
            fixture_bytes(&vector, "derived_key_hex")
        );
        assert_eq!(
            aad(&domain, revision, &binding).unwrap(),
            fixture_bytes(&vector, "aad_hex")
        );
        assert_eq!(
            open_with_domain(&master, &domain, revision, &binding, &envelope)
                .unwrap()
                .expose(),
            fixture_bytes(&vector, "plaintext_hex")
        );
        assert_eq!(
            &envelope[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES],
            fixture_bytes(&vector, "nonce_hex")
        );
        assert_eq!(
            envelope.len(),
            HEADER_BYTES + NONCE_BYTES + TAG_BYTES + fixture_bytes(&vector, "plaintext_hex").len()
        );
    }

    #[test]
    fn dynamic_and_static_domains_use_one_current_format_and_reject_untrusted_metadata() {
        let master = SecretKey::new([9; 32]);
        let plaintext = SecretBytes::new(b"secret".to_vec());
        let sealed = seal_with_domain(
            &master,
            Test::DOMAIN,
            Test::REVISION,
            b"object-1",
            &plaintext,
        )
        .unwrap();
        assert_eq!(
            open::<Test>(&master, b"object-1", &sealed)
                .unwrap()
                .expose(),
            b"secret"
        );
        let sealed = seal::<Test>(&master, b"object-1", &plaintext).unwrap();
        assert_eq!(
            open_with_domain(&master, Test::DOMAIN, Test::REVISION, b"object-1", &sealed)
                .unwrap()
                .expose(),
            b"secret"
        );
        assert_eq!(
            open_with_domain(
                &master,
                Test::DOMAIN,
                Test::REVISION + 1,
                b"object-1",
                &sealed
            )
            .unwrap_err(),
            Error::WrongRevision
        );
        assert_eq!(
            open_with_domain(
                &master,
                b"different/domain",
                Test::REVISION,
                b"object-1",
                &sealed
            )
            .unwrap_err(),
            Error::Authentication
        );
        let mut wrong_magic = sealed.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            open_with_domain(
                &master,
                Test::DOMAIN,
                Test::REVISION,
                b"object-1",
                &wrong_magic
            )
            .unwrap_err(),
            Error::WrongRevision
        );
        let oversized_domain = vec![0; MAX_DOMAIN_BYTES + 1];
        assert_eq!(
            seal_with_domain(&master, &oversized_domain, 1, b"object-1", &plaintext),
            Err(Error::DomainTooLarge)
        );
        let oversized_binding = vec![0; MAX_BINDING_BYTES + 1];
        assert_eq!(
            seal_with_domain(&master, Test::DOMAIN, 1, &oversized_binding, &plaintext),
            Err(Error::BindingTooLarge)
        );
    }

    #[test]
    fn roundtrip_is_bound_to_object_and_tampering_fails() {
        let key = SecretKey::new([9; 32]);
        let plain = SecretBytes::new(b"secret".to_vec());
        let sealed = seal::<Test>(&key, b"object-1", &plain).unwrap();
        assert_eq!(
            open::<Test>(&key, b"object-1", &sealed).unwrap().expose(),
            b"secret"
        );
        assert_eq!(
            open::<Test>(&key, b"object-2", &sealed).unwrap_err(),
            Error::Authentication
        );
        let mut corrupt = sealed;
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            open::<Test>(&key, b"object-1", &corrupt).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn binding_has_a_hard_allocation_limit() {
        let key = SecretKey::new([9; 32]);
        let plain = SecretBytes::new(b"secret".to_vec());
        let oversized = vec![b'x'; MAX_BINDING_BYTES + 1];
        assert_eq!(
            seal::<Test>(&key, &oversized, &plain),
            Err(Error::BindingTooLarge)
        );
        assert!(matches!(
            open::<Test>(&key, &oversized, &[0; 34]),
            Err(Error::BindingTooLarge)
        ));
    }
}
