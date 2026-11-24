/// SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism)
///
/// Implements the two message types we need to wrap NTLMv2:
///   - negTokenInit   — client initial token (wraps NTLM Type 1)
///   - negTokenResp   — subsequent tokens (wraps NTLM Type 2 or Type 3)
///
/// References:
///   RFC 4178 — SPNEGO
///   MS-SPNG  — Microsoft SPNEGO extension
///
/// We hand-build the DER encoding directly to avoid any ASN.1 library overhead.
use crate::asn1::{
    ctx, expect_tag, read_tlv, wrap_ctx, wrap_sequence, write_octet_string, write_oid, write_tlv,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use crate::error::{RdpError, Result};

// ── OID bytes ────────────────────────────────────────────────────────────────

/// SPNEGO OID: 1.3.6.1.5.5.2
/// Encoded: 2b 06 01 05 05 02
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
/// Encoded: 2b 06 01 04 01 82 37 02 02 0a
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

// ── negTokenInit ─────────────────────────────────────────────────────────────

/// Build a SPNEGO negTokenInit wrapping the NTLM Negotiate (Type 1) message.
///
/// ASN.1 structure:
///   initialContextToken (application-tagged [0]):
///     SEQUENCE {
///       thisMech OID (SPNEGO OID),
///       innerContextToken [0] {   <- negTokenInit
///         SEQUENCE {
///           mechTypes [0] SEQUENCE OF OID { NTLMSSP OID },
///           mechToken [2] OCTET STRING { ntlm_type1_bytes }
///         }
///       }
///     }
pub fn build_neg_token_init(ntlm_negotiate: &[u8]) -> Vec<u8> {
    tracing::debug!("SPNEGO: wrapping NTLM Type 1 (Negotiate) into GSS-API negTokenInit");
    // mechTypes SEQUENCE contains one OID: NTLMSSP
    let mut ntlmssp_oid = Vec::new();
    write_oid(OID_NTLMSSP, &mut ntlmssp_oid);

    let mut mech_types_seq = Vec::new();
    wrap_sequence(&ntlmssp_oid, &mut mech_types_seq);

    let mut mech_types_field = Vec::new();
    wrap_ctx(0, &mech_types_seq, &mut mech_types_field); // [0]

    // mechToken [2] OCTET STRING
    let mut mech_token_oct = Vec::new();
    write_octet_string(ntlm_negotiate, &mut mech_token_oct);

    let mut mech_token_field = Vec::new();
    wrap_ctx(2, &mech_token_oct, &mut mech_token_field); // [2]

    // negTokenInit SEQUENCE
    let mut neg_token_init_inner = Vec::new();
    neg_token_init_inner.extend_from_slice(&mech_types_field);
    neg_token_init_inner.extend_from_slice(&mech_token_field);

    let mut neg_token_init_seq = Vec::new();
    wrap_sequence(&neg_token_init_inner, &mut neg_token_init_seq);

    // [0] wrapping the negTokenInit
    let mut ctx0 = Vec::new();
    wrap_ctx(0, &neg_token_init_seq, &mut ctx0);

    // SPNEGO OID
    let mut spnego_oid = Vec::new();
    write_oid(OID_SPNEGO, &mut spnego_oid);

    // Outer SEQUENCE payload (implied by 0x60): { thisMech SPNEGO_OID, innerContextToken [0] negTokenInit }
    let mut outer_seq_inner = Vec::new();
    outer_seq_inner.extend_from_slice(&spnego_oid);
    outer_seq_inner.extend_from_slice(&ctx0);

    // Wrap in GSS-API Application tag [0] (0x60) directly (implied SEQUENCE)
    let mut out = Vec::new();
    write_tlv(0x60, &outer_seq_inner, &mut out);
    out
}

/// Build a SPNEGO negTokenResp wrapping an NTLM message (Type 3 Authenticate).
///
/// ASN.1 structure:
///   negTokenResp [1] {
///     SEQUENCE {
///       responseToken [2] OCTET STRING { ntlm_bytes }
///     }
///   }
pub fn build_neg_token_resp(ntlm_authenticate: &[u8]) -> Vec<u8> {
    tracing::debug!("SPNEGO: wrapping NTLM Type 3 (Authenticate) into negTokenResp");
    let mut oct = Vec::new();
    write_octet_string(ntlm_authenticate, &mut oct);

    let mut resp_token_field = Vec::new();
    wrap_ctx(2, &oct, &mut resp_token_field); // [2] responseToken

    let mut seq_inner = Vec::new();
    seq_inner.extend_from_slice(&resp_token_field);

    let mut seq = Vec::new();
    wrap_sequence(&seq_inner, &mut seq);

    let mut out = Vec::new();
    wrap_ctx(1, &seq, &mut out); // [1] negTokenResp
    out
}

// ── Token parser ─────────────────────────────────────────────────────────────

/// Extract the raw NTLM message bytes from either a negTokenInit [0] or
/// negTokenResp [1] SPNEGO token (handling both GSS-API wrapped and bare forms).
pub fn extract_ntlm_from_spnego(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(RdpError::Protocol("SPNEGO: empty token"));
    }
    tracing::debug!(
        "SPNEGO: extracting NTLM payload from token (outer tag: 0x{:02X}, len: {})",
        data[0],
        data.len()
    );

    // First try: GSS-API application tag 0x60
    if data[0] == 0x60 {
        return extract_from_gss_init(data);
    }

    // [0] negTokenInit
    if data[0] == ctx(0) {
        return extract_token_from_ctx(data, 0);
    }

    // [1] negTokenResp
    if data[0] == ctx(1) {
        return extract_token_from_ctx(data, 1);
    }

    Err(RdpError::ProtocolMsg(format!(
        "SPNEGO: unrecognised outer tag 0x{:02X}",
        data[0]
    )))
}

fn extract_from_gss_init(data: &[u8]) -> Result<Vec<u8>> {
    // 0x60 { OID(SPNEGO), [0] negTokenInit }
    let (app_val, _) = expect_tag(data, 0, 0x60)?;

    // Skip the OID
    let (_, after_oid) = expect_tag(app_val, 0, TAG_OID)?;

    // [0] negTokenInit
    let (ctx0_val, _) = expect_tag(app_val, after_oid, ctx(0))?;
    let (neg_seq_val, _) = expect_tag(ctx0_val, 0, TAG_SEQUENCE)?;

    // Scan for [2] mechToken
    extract_field_ctx2(neg_seq_val)
}

fn extract_token_from_ctx(data: &[u8], tag_n: u8) -> Result<Vec<u8>> {
    let (ctx_val, _) = expect_tag(data, 0, ctx(tag_n))?;
    let (seq_val, _) = expect_tag(ctx_val, 0, TAG_SEQUENCE)?;
    extract_field_ctx2(seq_val)
}

/// Find the [2] responseToken / mechToken field in a negTokenInit/Resp sequence body.
fn extract_field_ctx2(seq_body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    while pos < seq_body.len() {
        let (tag, val, next) = read_tlv(seq_body, pos)?;
        if tag == ctx(2) {
            // value is OCTET STRING
            let (oct_val, _) = expect_tag(val, 0, TAG_OCTET_STRING)?;
            tracing::debug!(
                "SPNEGO: found NTLM payload in field [2] ({} bytes)",
                oct_val.len()
            );
            return Ok(oct_val.to_vec());
        }
        pos = next;
    }
    Err(RdpError::Protocol(
        "SPNEGO: [2] mechToken/responseToken not found",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::build_negotiate;

    #[test]
    fn neg_token_init_roundtrip() {
        let negotiate = build_negotiate();
        let token = build_neg_token_init(&negotiate);

        // Outer tag should be 0x60 (GSS-API)
        assert_eq!(token[0], 0x60);

        // Round-trip: extract NTLM bytes back
        let extracted = extract_ntlm_from_spnego(&token).unwrap();
        assert_eq!(extracted, negotiate);
    }

    #[test]
    fn neg_token_resp_structure() {
        let fake_ntlm = b"NTLMSSP\x00\x03\x00\x00\x00";
        let token = build_neg_token_resp(fake_ntlm);
        // Outer tag = [1]
        assert_eq!(token[0], ctx(1));
    }
}
