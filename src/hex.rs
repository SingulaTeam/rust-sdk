//! Lowercase hex, for the identifiers and nonces the protocol writes as text.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `bytes` as lowercase hex, two digits per byte.
pub(crate) fn lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0xf)]])
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn writes_two_digits_per_byte() {
        assert_eq!(super::lower(&[0x00, 0x0a, 0xff]), "000aff");
    }
}
