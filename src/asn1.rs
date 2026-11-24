/// Minimal BER/DER ASN.1 encoder/decoder.
///
/// Only the tags that CredSSP (MS-CSSP) and SPNEGO actually use:
///   - SEQUENCE (0x30)
///   - CONTEXT-tagged (0xA0..0xBF)
///   - OCTET STRING (0x04)
///   - OBJECT IDENTIFIER (0x06)
///   - ENUMERATED (0x0A)
///   - INTEGER (0x02)
///   - GENERAL STRING (0x1B)
///
/// All length encodings follow DER canonical form (shortest encoding).
use crate::error::{RdpError, Result};

// ──────────────────────────────────────────────────────────────────────────────
// Tag constants
// ──────────────────────────────────────────────────────────────────────────────

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_ENUMERATED: u8 = 0x0A;
pub const TAG_SEQUENCE: u8 = 0x30; // SEQUENCE OF
pub const TAG_SET: u8 = 0x31;

/// Context-specific, constructed tag [N].
pub const fn ctx(n: u8) -> u8 {
    0xA0 | n
}
/// Context-specific, primitive tag [N].
pub const fn ctx_prim(n: u8) -> u8 {
    0x80 | n
}

// ──────────────────────────────────────────────────────────────────────────────
// Length helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Encode a DER length into `out`.
pub fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        // Up to 3 extra bytes — sufficient for CredSSP
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

/// How many bytes `encode_len(len)` will produce.
pub fn len_of_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else if len <= 0xFFFF {
        3
    } else {
        4
    }
}

/// Total TLV size for a given tag+value length.
pub fn tlv_size(value_len: usize) -> usize {
    1 + len_of_len(value_len) + value_len
}

/// Decode a DER length from `data[pos..]`, returning `(length, new_pos)`.
pub fn decode_len(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    if pos >= data.len() {
        return Err(RdpError::Protocol("ASN.1: truncated length"));
    }
    let first = data[pos];
    if first < 0x80 {
        Ok((first as usize, pos + 1))
    } else {
        let extra = (first & 0x7F) as usize;
        if extra == 0 || extra > 4 {
            return Err(RdpError::Protocol("ASN.1: indefinite or oversized length"));
        }
        if pos + 1 + extra > data.len() {
            return Err(RdpError::Protocol("ASN.1: truncated multi-byte length"));
        }
        let mut len = 0usize;
        for i in 0..extra {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        Ok((len, pos + 1 + extra))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLV read helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Read one TLV at `pos`, return `(tag, value_slice, next_pos)`.
pub fn read_tlv(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize)> {
    if pos >= data.len() {
        return Err(RdpError::Protocol("ASN.1: unexpected end of data"));
    }
    let tag = data[pos];
    let (len, vstart) = decode_len(data, pos + 1)?;
    let vend = vstart + len;
    if vend > data.len() {
        return Err(RdpError::Protocol("ASN.1: value extends past buffer"));
    }
    Ok((tag, &data[vstart..vend], vend))
}

/// Expect a specific tag, return value bytes.
pub fn expect_tag(data: &[u8], pos: usize, tag: u8) -> Result<(&[u8], usize)> {
    let (actual_tag, value, next) = read_tlv(data, pos)?;
    if actual_tag != tag {
        return Err(RdpError::ProtocolMsg(format!(
            "ASN.1: expected tag 0x{tag:02X}, got 0x{actual_tag:02X}"
        )));
    }
    Ok((value, next))
}

/// Read a DER INTEGER as i64.
pub fn read_integer(data: &[u8], pos: usize) -> Result<(i64, usize)> {
    let (bytes, next) = expect_tag(data, pos, TAG_INTEGER)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(RdpError::Protocol("ASN.1: invalid integer length"));
    }
    let mut val = if bytes[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    Ok((val, next))
}

/// Read a DER ENUMERATED as i64.
pub fn read_enumerated(data: &[u8], pos: usize) -> Result<(i64, usize)> {
    let (bytes, next) = expect_tag(data, pos, TAG_ENUMERATED)?;
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(RdpError::Protocol("ASN.1: invalid enumerated length"));
    }
    let mut val = 0i64;
    for &b in bytes {
        val = (val << 8) | (b as i64);
    }
    Ok((val, next))
}

// ──────────────────────────────────────────────────────────────────────────────
// TLV write helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Write a TLV with given tag and value into `out`.
pub fn write_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    encode_len(value.len(), out);
    out.extend_from_slice(value);
}

/// Wrap `inner` in a SEQUENCE.
pub fn wrap_sequence(inner: &[u8], out: &mut Vec<u8>) {
    write_tlv(TAG_SEQUENCE, inner, out);
}

/// Wrap `inner` in a context-specific constructed [N].
pub fn wrap_ctx(n: u8, inner: &[u8], out: &mut Vec<u8>) {
    write_tlv(ctx(n), inner, out);
}

/// Encode an OCTET STRING.
pub fn write_octet_string(data: &[u8], out: &mut Vec<u8>) {
    write_tlv(TAG_OCTET_STRING, data, out);
}

/// Encode an OID (raw encoded bytes, no first-octet computation here).
pub fn write_oid(oid_bytes: &[u8], out: &mut Vec<u8>) {
    write_tlv(TAG_OID, oid_bytes, out);
}

/// Encode an INTEGER from a u32.
pub fn write_integer_u32(val: u32, out: &mut Vec<u8>) {
    let bytes = if val <= 0x7F {
        vec![val as u8]
    } else if val <= 0x7FFF {
        vec![(val >> 8) as u8, (val & 0xFF) as u8]
    } else if val <= 0x7FFFFF {
        vec![(val >> 16) as u8, (val >> 8) as u8, (val & 0xFF) as u8]
    } else {
        // Add leading 0x00 if high bit is set to keep it positive
        let b = val.to_be_bytes();
        if b[0] & 0x80 != 0 {
            vec![0x00, b[0], b[1], b[2], b[3]]
        } else {
            b.to_vec()
        }
    };
    write_tlv(TAG_INTEGER, &bytes, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_octet_string() {
        let data = b"hello world";
        let mut out = Vec::new();
        write_octet_string(data, &mut out);
        let (val, _) = expect_tag(&out, 0, TAG_OCTET_STRING).unwrap();
        assert_eq!(val, data);
    }

    #[test]
    fn nested_sequence() {
        let mut inner = Vec::new();
        write_octet_string(b"test", &mut inner);
        let mut out = Vec::new();
        wrap_sequence(&inner, &mut out);

        let (seq_val, _) = expect_tag(&out, 0, TAG_SEQUENCE).unwrap();
        let (oct_val, _) = expect_tag(seq_val, 0, TAG_OCTET_STRING).unwrap();
        assert_eq!(oct_val, b"test");
    }

    #[test]
    fn large_length_encoding() {
        let big = vec![0xABu8; 300];
        let mut out = Vec::new();
        write_octet_string(&big, &mut out);
        // Length 300 = 0x12C → encoded as 0x82 0x01 0x2C
        assert_eq!(out[1], 0x82);
        let (val, _) = expect_tag(&out, 0, TAG_OCTET_STRING).unwrap();
        assert_eq!(val.len(), 300);
    }
}
