//! This module contains some helper functions to avoid having to call into the expensive fmt code.

pub const MAX_INT_DIGITS: usize = 11;

/// Writes ascii bytes to the buffer to represent the given int value.
///
/// Returns the slice of the buffer that was written to.
/// It can be used as a value or to determine the length of the formatting.
///
/// Panics if the buffer is less than [MAX_INT_DIGITS] long.
pub fn write_int(buffer: &mut [u8], value: i32) -> &mut [u8] {
    // Check in debug mode if the buffer is long enough.
    // We don't do this in release to have less overhead.
    debug_assert!(buffer.len() >= MAX_INT_DIGITS);

    let mut buffer_index = 0;
    let is_negative = value.is_negative();

    if value == 0{
        buffer[buffer_index] = b'0';
        buffer_index += 1;
        return &mut buffer[0..buffer_index];
    }

    if is_negative {
        buffer[buffer_index] = b'-';
        buffer_index += 1;
    }

    // We already checked for negative, take the absolute value and keep working on it
    let mut number = value.unsigned_abs();
    // Calculate the number of digits by using logarithm.
    let mut n_digits = number.ilog10() as i32;


    while n_digits >= 0 {
        // For each iteration we will take the biggest number of the value and put it into the buffer
        let div = 10u32.pow(n_digits as u32).max(1);
        let current_number = number / div;
        // Make the number the full number so we can adjust the number correctly
        number -= current_number * div;
        buffer[buffer_index] = b'0' + current_number as u8;
        buffer_index += 1;
        n_digits -= 1;
    }

    debug_assert!(number == 0, "In this point the number should be 0, which asserts that we wrote it OK");

    &mut buffer[0..buffer_index]
}

/// Parses an int
pub fn parse_int(buffer: &[u8]) -> Option<i32> {
    if buffer.is_empty() || buffer.len() > MAX_INT_DIGITS {
        return None;
    }
    core::str::from_utf8(buffer).ok()?.parse::<i32>().ok()
}

/// The size that occupies a byte in hex format
const HEX_BYTE_SIZE: usize = 2;

/// Helper function that given a byte returns the corresponding ASCII nibble (4 bytes)
/// for the given [byte].
/// [byte] must be between 0 and 15 inclusive
fn get_ascii(byte: u8) -> u8 {
    // By definition by min is 0
    debug_assert!(byte <= 15, "The provided byte must be in range [0, 15]");
    match byte {
        0..=9 => b'0' + byte,
        10..=15 => b'a' + byte - 10,
        _ => unreachable!(),
    }
}

/// Given a byte returns a byte slice which contains the ASCII hex representation.
pub fn parse_byte_to_hex(byte: u8) -> [u8; HEX_BYTE_SIZE] {
    let top = byte >> 4;
    let bottom = byte & 0x0f;

    [get_ascii(top), get_ascii(bottom)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec::Vec;

    #[test]
    fn test_write_int() {
        let mut buffer = [0; 128];

        assert_eq!(write_int(&mut buffer, 0), b"0");
        assert_eq!(write_int(&mut buffer, -1), b"-1");
        assert_eq!(write_int(&mut buffer, 1), b"1");
        assert_eq!(write_int(&mut buffer, -42), b"-42");
        assert_eq!(write_int(&mut buffer, 42), b"42");
        assert_eq!(write_int(&mut buffer, -2147483648), b"-2147483648");
        assert_eq!(write_int(&mut buffer, 2147483647), b"2147483647");
    }

    #[test]
    fn test_parse_int() {
        assert_eq!(parse_int(b"0"), Some(0));
        assert_eq!(parse_int(b"-1"), Some(-1));
        assert_eq!(parse_int(b"1"), Some(1));
        assert_eq!(parse_int(b"-42"), Some(-42));
        assert_eq!(parse_int(b"42"), Some(42));
        assert_eq!(parse_int(b"-2147483648"), Some(-2147483648));
        assert_eq!(parse_int(b"2147483647"), Some(2147483647));

        assert_eq!(parse_int(b""), None);
        assert_eq!(parse_int(b"abc"), None);
        assert_eq!(parse_int(b"-b"), None);
        assert_eq!(parse_int(b"123456a"), None);
        assert_eq!(parse_int(b"z12354"), None);
    }

    #[test]
    fn test_byte_to_hex() {
        let expecting: Vec<u8> = (b'0'..=b'9').chain(b'a'..=b'f').collect();
        for i in 0..15 {
            let ascii_value = get_ascii(i);
            let expected = expecting[i as usize];
            assert_eq!(ascii_value, expected)
        }
    }

    #[test]
    #[should_panic]
    fn test_byte_to_hex_invalid() {
        get_ascii(0x97);
    }

    #[test]
    fn test_parse_byte_to_hex() {
        for i in 0u8..=255u8 {
            let expecting = format!("{:02x}", i);
            let got = parse_byte_to_hex(i);
            assert_eq!(expecting.as_bytes(), got);
        }
    }
}
