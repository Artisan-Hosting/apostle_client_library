use dusa_collection_utils::core::errors::{ErrorArrayItem, Errors};

/// Fixed 12-byte prefix of an X25519 `SubjectPublicKeyInfo` DER encoding (RFC 8410):
/// `SEQUENCE { SEQUENCE { OID 1.3.101.110 }, BIT STRING { <32 raw key bytes> } }`.
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

/// Extracts the raw 32-byte X25519 key from a DER-encoded `SubjectPublicKeyInfo`.
///
/// The encoding for an X25519 key is fixed-shape (RFC 8410), so this is a plain
/// length + prefix check followed by a slice, rather than a full ASN.1 parse.
pub fn parse_x25519_spki_der(der: &[u8]) -> Result<[u8; 32], ErrorArrayItem> {
    if der.len() != 44 || der[..12] != X25519_SPKI_PREFIX {
        return Err(ErrorArrayItem::new(
            Errors::ConfigParsing,
            "not a valid X25519 SubjectPublicKeyInfo DER".to_owned(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&der[12..]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_DER: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00, 4, 174, 4, 246,
        179, 162, 129, 67, 40, 38, 19, 206, 110, 212, 181, 156, 135, 163, 139, 211, 132, 147, 103,
        80, 141, 7, 41, 46, 32, 80, 190, 84,
    ];

    #[test]
    fn parses_valid_der() {
        let key = parse_x25519_spki_der(&VALID_DER).expect("should parse");
        assert_eq!(&key, &VALID_DER[12..]);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_x25519_spki_der(&VALID_DER[..40]).is_err());
    }

    #[test]
    fn rejects_bad_prefix() {
        let mut bad = VALID_DER;
        bad[0] = 0x00;
        assert!(parse_x25519_spki_der(&bad).is_err());
    }
}
