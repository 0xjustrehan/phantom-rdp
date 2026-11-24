/// X.224 Connection layer — MS-RDPBCGR §2.2.1.1 / §2.2.1.2
///
/// We only implement the two PDUs needed for NLA negotiation:
///  - Connection Request  (CR)  — Class 0, TPDU code 0xE0
///  - Connection Confirm  (CC)  — Class 0, TPDU code 0xD0
///
/// The CR includes a Routing Token / Cookie and the RDP Negotiation Request
/// advertising PROTOCOL_HYBRID (CredSSP / NLA).
use crate::error::{RdpError, Result};

// ── RDP_NEG_REQ constants ────────────────────────────────────────────────────

/// RDP Negotiation Request type identifier.
const TYPE_RDP_NEG_REQ: u8 = 0x01;
/// RDP Negotiation Response type identifier.
const TYPE_RDP_NEG_RSP: u8 = 0x02;
/// RDP Negotiation Failure type identifier.
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

/// Request NLA (CredSSP).
pub const PROTOCOL_HYBRID: u32 = 0x00000002;
/// Also accept SSL.
pub const PROTOCOL_SSL: u32 = 0x00000001;
/// Classic RDP security (we never use this but record it).
pub const PROTOCOL_RDP: u32 = 0x00000000;

// ── X.224 TPDU codes ─────────────────────────────────────────────────────────

const CR_TPDU: u8 = 0xE0; // Connection Request
const CC_TPDU: u8 = 0xD0; // Connection Confirm

// ── Builders ─────────────────────────────────────────────────────────────────

/// Build an X.224 Connection Request PDU payload (everything after TPKT header).
///
/// Layout:
///  [0]      Length indicator (LI) — number of bytes after LI in the fixed header
///  [1]      TPDU Code | 0  (upper nibble = 0xE, lower = 0)
///  [2..3]   DST-REF = 0x0000
///  [4..5]   SRC-REF = 0x0000
///  [6]      Class option = 0x00
///  [7..]    Variable part: cookie + RDP_NEG_REQ
pub fn build_connection_request(cookie: Option<&str>) -> Vec<u8> {
    tracing::debug!("X.224: building Connection Request (cookie={:?}, requested=PROTOCOL_HYBRID | PROTOCOL_SSL)", cookie);
    // Build the variable part first so we know the total length.
    let mut var: Vec<u8> = Vec::with_capacity(64);

    // Routing token cookie — e.g. "Cookie: mstshash=anonymous\r\n"
    if let Some(c) = cookie {
        let line = format!("Cookie: mstshash={c}\r\n");
        var.extend_from_slice(line.as_bytes());
    }

    // RDP Negotiation Request (8 bytes) — request PROTOCOL_HYBRID
    let requested = PROTOCOL_HYBRID | PROTOCOL_SSL;
    var.push(TYPE_RDP_NEG_REQ); // type
    var.push(0x00); // flags
    var.extend_from_slice(&8u16.to_le_bytes()); // length = 8
    var.extend_from_slice(&requested.to_le_bytes()); // requestedProtocols

    // Fixed header is 7 bytes (LI + code + dst-ref + src-ref + class).
    // LI is the length indicator of the entire rest of the PDU, which is
    // 6 bytes of the fixed header + the variable part.
    // LI must fit in a u8 (max 255). If the variable part is too large (e.g. very long cookie),
    // fall back to no cookie to ensure a valid PDU.
    let li_usize = 6 + var.len();
    let li = if li_usize > 255 {
        tracing::warn!("X.224: variable part too large ({} bytes), stripping cookie to fit LI in u8", var.len());
        // Recompute var without the cookie — only keep the 8-byte RDP_NEG_REQ
        var.truncate(8); // RDP_NEG_REQ is exactly 8 bytes
        (6 + var.len()) as u8
    } else {
        li_usize as u8
    };

    let mut pdu: Vec<u8> = Vec::with_capacity(7 + var.len());
    pdu.push(li);
    pdu.push(CR_TPDU);
    pdu.extend_from_slice(&[0x00, 0x00]); // DST-REF
    pdu.extend_from_slice(&[0x00, 0x00]); // SRC-REF
    pdu.push(0x00); // Class option
    pdu.extend_from_slice(&var);
    pdu
}

// ── Parsed Connection Confirm ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConnectionConfirm {
    /// The protocol the server agreed to.
    pub selected_protocol: u32,
}

/// Parse an X.224 Connection Confirm PDU payload (after the TPKT header).
pub fn parse_connection_confirm(data: &[u8]) -> Result<ConnectionConfirm> {
    // Minimum fixed header: LI + code + dst-ref(2) + src-ref(2) + class = 7 bytes
    if data.len() < 7 {
        return Err(RdpError::Protocol("X.224 CC: payload too short"));
    }

    let _li = data[0];
    let code = data[1];
    if code != CC_TPDU {
        return Err(RdpError::ProtocolMsg(format!(
            "X.224: expected CC (0xD0), got 0x{code:02X}"
        )));
    }

    // Variable part starts at offset 7
    let var = &data[7..];
    parse_neg_response(var)
}

fn parse_neg_response(var: &[u8]) -> Result<ConnectionConfirm> {
    if var.is_empty() {
        tracing::debug!("X.224: empty negotiation response, assuming classic RDP");
        // Server accepted with no negotiation response — assume RDP classic.
        return Ok(ConnectionConfirm {
            selected_protocol: PROTOCOL_RDP,
        });
    }

    let neg_type = var[0];
    match neg_type {
        TYPE_RDP_NEG_RSP => {
            if var.len() < 8 {
                return Err(RdpError::Protocol("X.224 NEG_RSP: too short"));
            }
            let selected = u32::from_le_bytes(var[4..8].try_into().unwrap());
            tracing::debug!(
                "X.224: received NEG_RSP (selected_protocol=0x{:08X})",
                selected
            );
            Ok(ConnectionConfirm {
                selected_protocol: selected,
            })
        }
        TYPE_RDP_NEG_FAILURE => {
            if var.len() < 8 {
                return Err(RdpError::Protocol("X.224 NEG_FAILURE: too short"));
            }
            let code = u32::from_le_bytes(var[4..8].try_into().unwrap());
            Err(RdpError::ProtocolMsg(format!(
                "X.224 Negotiation Failure: code 0x{code:08X}"
            )))
        }
        other => Err(RdpError::ProtocolMsg(format!(
            "X.224: unknown neg type 0x{other:02X}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_basic_structure() {
        let pdu = build_connection_request(Some("anonymous"));
        // First byte = LI = 6 + 36 (cookie len + neg req len) = 42
        assert_eq!(pdu[0], 42);
        // Second byte = TPDU code
        assert_eq!(pdu[1], CR_TPDU);
    }

    #[test]
    fn parse_cc_hybrid() {
        // Construct a minimal CC PDU with NEG_RSP selecting HYBRID
        let mut pdu = vec![
            6u8,     // LI
            CC_TPDU, // code
            0, 0, // dst-ref
            0, 0, // src-ref
            0, // class
        ];
        // NEG_RSP
        pdu.push(TYPE_RDP_NEG_RSP);
        pdu.push(0x00); // flags
        pdu.extend_from_slice(&8u16.to_le_bytes());
        pdu.extend_from_slice(&PROTOCOL_HYBRID.to_le_bytes());

        let cc = parse_connection_confirm(&pdu).unwrap();
        assert_eq!(cc.selected_protocol, PROTOCOL_HYBRID);
    }
}
