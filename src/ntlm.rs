/// Full NTLMv2 implementation — MS-NLMP
///
/// Implements the complete NTLMv2 authentication flow:
///   1. Build NEGOTIATE message (Type 1)
///   2. Parse CHALLENGE message (Type 2) — extract ServerChallenge + TargetInfo
///   3. Build AUTHENTICATE message (Type 3)
///      - NTOWFv2 (HMAC_MD5 of MD4(unicode(password)))
///      - NtChallengeResponse blob (timestamp, client challenge, AV_PAIR chain)
///      - NtProofStr, SessionBaseKey, EncryptedRandomSessionKey
///      - MIC (Message Integrity Code)
///
/// All crypto is pure Rust — no OpenSSL, no native dependencies.
use crate::error::{RdpError, Result};
use hmac::{Hmac, Mac};
use md5::Md5;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacMd5 = Hmac<Md5>;

// ──────────────────────────────────────────────────────────────────────────────
// Inline RC4 (avoids generic_array type ambiguity from the rc4 crate)
// ──────────────────────────────────────────────────────────────────────────────

fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut out = data.to_vec();
    let (mut i, mut j) = (0usize, 0usize);
    for byte in out.iter_mut() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) % 256];
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Constants from MS-NLMP
// ──────────────────────────────────────────────────────────────────────────────

const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

// MessageType values
const NTLMSSP_NEGOTIATE: u32 = 1;
const NTLMSSP_CHALLENGE: u32 = 2;
const NTLMSSP_AUTH: u32 = 3;

// Negotiate Flags — we pick the minimal set required for NTLMv2 + NLA
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_REQUEST_TARGET: u32 = 0x0000_0004;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
#[allow(dead_code)]
const NTLMSSP_REQUEST_NON_NT_SESSION_KEY: u32 = 0x0040_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
#[allow(dead_code)]
const NTLMSSP_NEGOTIATE_TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;

// AV_PAIR MsvAvId values
const MS_AV_EOL: u16 = 0x0000;
const MS_AV_NB_COMPUTER_NAME: u16 = 0x0001;
const MS_AV_NB_DOMAIN_NAME: u16 = 0x0002;
#[allow(dead_code)]
const MS_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
const MS_AV_DNS_DOMAIN_NAME: u16 = 0x0004;
const MS_AV_DNS_TREE_NAME: u16 = 0x0005;
#[allow(dead_code, non_upper_case_globals)]
const MS_AV_FLAGS: u16 = 0x0006;
#[allow(dead_code, non_upper_case_globals)]
const MS_AV_TIMESTAMP: u16 = 0x0007;
#[allow(dead_code, non_upper_case_globals)]
const MsAvSingleHost: u16 = 0x0008;
#[allow(dead_code, non_upper_case_globals)]
const MsAvTargetName: u16 = 0x0009;
#[allow(dead_code, non_upper_case_globals)]
const MsAvChannelBindings: u16 = 0x000A;

// Negotiate flags we will use in our messages (Type 1 Negotiate)
const NEGOTIATE_FLAGS: u32 = NTLMSSP_NEGOTIATE_56
    | NTLMSSP_NEGOTIATE_KEY_EXCH
    | NTLMSSP_NEGOTIATE_128
    | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NTLMSSP_NEGOTIATE_NTLM
    | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    | NTLMSSP_NEGOTIATE_REQUEST_TARGET
    | NTLMSSP_NEGOTIATE_UNICODE
    | NTLMSSP_NEGOTIATE_VERSION
    | NTLMSSP_NEGOTIATE_SEAL
    | NTLMSSP_NEGOTIATE_SIGN
    | NTLMSSP_NEGOTIATE_OEM;

// ──────────────────────────────────────────────────────────────────────────────
// MD4 (pure Rust — needed for NTOWFv1/v2 password hashing)
// ──────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn md4_g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn md4_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
pub fn fast_md4_block(x: &[u32; 16]) -> [u8; 16] {
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;

    // Round 1 (with pre-computed IV constants)
    let mut a = (x[0].wrapping_sub(1)).rotate_left(3);
    d = (d.wrapping_add(x[1]).wrapping_add(0x98badcfe ^ (a & 0x77777777))).rotate_left(7);
    c = (c.wrapping_add(x[2]).wrapping_add(b ^ (d & (a ^ b)))).rotate_left(11);
    b = (b.wrapping_add(x[3]).wrapping_add(a ^ (c & (d ^ a)))).rotate_left(19);

    a = (a.wrapping_add(x[4]).wrapping_add(d ^ (b & (c ^ d)))).rotate_left(3);
    d = (d.wrapping_add(x[5]).wrapping_add(c ^ (a & (b ^ c)))).rotate_left(7);
    c = (c.wrapping_add(x[6]).wrapping_add(b ^ (d & (a ^ b)))).rotate_left(11);
    b = (b.wrapping_add(x[7]).wrapping_add(a ^ (c & (d ^ a)))).rotate_left(19);

    a = (a.wrapping_add(x[8]).wrapping_add(d ^ (b & (c ^ d)))).rotate_left(3);
    d = (d.wrapping_add(x[9]).wrapping_add(c ^ (a & (b ^ c)))).rotate_left(7);
    c = (c.wrapping_add(x[10]).wrapping_add(b ^ (d & (a ^ b)))).rotate_left(11);
    b = (b.wrapping_add(x[11]).wrapping_add(a ^ (c & (d ^ a)))).rotate_left(19);

    a = (a.wrapping_add(x[12]).wrapping_add(d ^ (b & (c ^ d)))).rotate_left(3);
    d = (d.wrapping_add(x[13]).wrapping_add(c ^ (a & (b ^ c)))).rotate_left(7);
    c = (c.wrapping_add(x[14]).wrapping_add(b ^ (d & (a ^ b)))).rotate_left(11);
    b = (b.wrapping_add(x[15]).wrapping_add(a ^ (c & (d ^ a)))).rotate_left(19);

    // Round 2
    a = (a.wrapping_add(md4_g(b, c, d)).wrapping_add(x[0]).wrapping_add(0x5a827999)).rotate_left(3);
    d = (d.wrapping_add(md4_g(a, b, c)).wrapping_add(x[4]).wrapping_add(0x5a827999)).rotate_left(5);
    c = (c.wrapping_add(md4_g(d, a, b)).wrapping_add(x[8]).wrapping_add(0x5a827999)).rotate_left(9);
    b = (b.wrapping_add(md4_g(c, d, a)).wrapping_add(x[12]).wrapping_add(0x5a827999)).rotate_left(13);

    a = (a.wrapping_add(md4_g(b, c, d)).wrapping_add(x[1]).wrapping_add(0x5a827999)).rotate_left(3);
    d = (d.wrapping_add(md4_g(a, b, c)).wrapping_add(x[5]).wrapping_add(0x5a827999)).rotate_left(5);
    c = (c.wrapping_add(md4_g(d, a, b)).wrapping_add(x[9]).wrapping_add(0x5a827999)).rotate_left(9);
    b = (b.wrapping_add(md4_g(c, d, a)).wrapping_add(x[13]).wrapping_add(0x5a827999)).rotate_left(13);

    a = (a.wrapping_add(md4_g(b, c, d)).wrapping_add(x[2]).wrapping_add(0x5a827999)).rotate_left(3);
    d = (d.wrapping_add(md4_g(a, b, c)).wrapping_add(x[6]).wrapping_add(0x5a827999)).rotate_left(5);
    c = (c.wrapping_add(md4_g(d, a, b)).wrapping_add(x[10]).wrapping_add(0x5a827999)).rotate_left(9);
    b = (b.wrapping_add(md4_g(c, d, a)).wrapping_add(x[14]).wrapping_add(0x5a827999)).rotate_left(13);

    a = (a.wrapping_add(md4_g(b, c, d)).wrapping_add(x[3]).wrapping_add(0x5a827999)).rotate_left(3);
    d = (d.wrapping_add(md4_g(a, b, c)).wrapping_add(x[7]).wrapping_add(0x5a827999)).rotate_left(5);
    c = (c.wrapping_add(md4_g(d, a, b)).wrapping_add(x[11]).wrapping_add(0x5a827999)).rotate_left(9);
    b = (b.wrapping_add(md4_g(c, d, a)).wrapping_add(x[15]).wrapping_add(0x5a827999)).rotate_left(13);

    // Round 3
    a = (a.wrapping_add(md4_h(b, c, d)).wrapping_add(x[0]).wrapping_add(0x6ed9eba1)).rotate_left(3);
    d = (d.wrapping_add(md4_h(a, b, c)).wrapping_add(x[8]).wrapping_add(0x6ed9eba1)).rotate_left(9);
    c = (c.wrapping_add(md4_h(d, a, b)).wrapping_add(x[4]).wrapping_add(0x6ed9eba1)).rotate_left(11);
    b = (b.wrapping_add(md4_h(c, d, a)).wrapping_add(x[12]).wrapping_add(0x6ed9eba1)).rotate_left(15);

    a = (a.wrapping_add(md4_h(b, c, d)).wrapping_add(x[2]).wrapping_add(0x6ed9eba1)).rotate_left(3);
    d = (d.wrapping_add(md4_h(a, b, c)).wrapping_add(x[10]).wrapping_add(0x6ed9eba1)).rotate_left(9);
    c = (c.wrapping_add(md4_h(d, a, b)).wrapping_add(x[6]).wrapping_add(0x6ed9eba1)).rotate_left(11);
    b = (b.wrapping_add(md4_h(c, d, a)).wrapping_add(x[14]).wrapping_add(0x6ed9eba1)).rotate_left(15);

    a = (a.wrapping_add(md4_h(b, c, d)).wrapping_add(x[1]).wrapping_add(0x6ed9eba1)).rotate_left(3);
    d = (d.wrapping_add(md4_h(a, b, c)).wrapping_add(x[9]).wrapping_add(0x6ed9eba1)).rotate_left(9);
    c = (c.wrapping_add(md4_h(d, a, b)).wrapping_add(x[5]).wrapping_add(0x6ed9eba1)).rotate_left(11);
    b = (b.wrapping_add(md4_h(c, d, a)).wrapping_add(x[13]).wrapping_add(0x6ed9eba1)).rotate_left(15);

    a = (a.wrapping_add(md4_h(b, c, d)).wrapping_add(x[3]).wrapping_add(0x6ed9eba1)).rotate_left(3);
    d = (d.wrapping_add(md4_h(a, b, c)).wrapping_add(x[11]).wrapping_add(0x6ed9eba1)).rotate_left(9);
    c = (c.wrapping_add(md4_h(d, a, b)).wrapping_add(x[7]).wrapping_add(0x6ed9eba1)).rotate_left(11);
    b = (b.wrapping_add(md4_h(c, d, a)).wrapping_add(x[15]).wrapping_add(0x6ed9eba1)).rotate_left(15);

    let a_out = a.wrapping_add(0x67452301);
    let b_out = b.wrapping_add(0xefcdab89);
    let c_out = c.wrapping_add(0x98badcfe);
    let d_out = d.wrapping_add(0x10325476);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a_out.to_le_bytes());
    out[4..8].copy_from_slice(&b_out.to_le_bytes());
    out[8..12].copy_from_slice(&c_out.to_le_bytes());
    out[12..16].copy_from_slice(&d_out.to_le_bytes());
    out
}

pub fn md4(input: &[u8]) -> [u8; 16] {
    if input.len() <= 55 {
        let mut block = [0u8; 64];
        block[..input.len()].copy_from_slice(input);
        block[input.len()] = 0x80;
        let bit_len = (input.len() as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_le_bytes());

        let mut x = [0u32; 16];
        for i in 0..16 {
            let b0 = block[i * 4] as u32;
            let b1 = block[i * 4 + 1] as u32;
            let b2 = block[i * 4 + 2] as u32;
            let b3 = block[i * 4 + 3] as u32;
            x[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        fast_md4_block(&x)
    } else {
        use md4::{Digest, Md4};
        let mut hasher = Md4::new();
        hasher.update(input);
        let result = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&result);
        out
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unicode helper
// ──────────────────────────────────────────────────────────────────────────────

/// Encode string as UTF-16LE (as required by NTLM).
pub fn unicode(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// HMAC-MD5 helper
// ──────────────────────────────────────────────────────────────────────────────

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5: any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// NTOWFv2
// ──────────────────────────────────────────────────────────────────────────────

/// High-speed zero-allocation NTOWFv2 derivation directly from an existing NT hash.
pub fn ntowf_v2_from_hash(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(nt_hash).expect("HMAC-MD5 key");
    let mut buf = [0u16; 2];
    for c in username.chars() {
        for uc in c.to_uppercase() {
            for &u in uc.encode_utf16(&mut buf) as &[u16] {
                mac.update(&u.to_le_bytes());
            }
        }
    }
    for c in domain.encode_utf16() {
        mac.update(&c.to_le_bytes());
    }
    mac.finalize().into_bytes().into()
}

/// NTOWFv2: HMAC_MD5(MD4(unicode(password)), unicode(upper(user) + domain))
/// Returns the 16-byte ResponseKeyNT.
pub fn ntowf_v2(password: &str, username: &str, domain: &str) -> [u8; 16] {
    let nt_hash = if password.len() == 32 && password.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut hash = [0u8; 16];
        let mut valid = true;
        for i in 0..16 {
            if let Ok(val) = u8::from_str_radix(&password[i * 2..i * 2 + 2], 16) {
                hash[i] = val;
            } else {
                valid = false;
                break;
            }
        }
        if valid {
            hash
        } else {
            compute_nt_hash(password)
        }
    } else {
        compute_nt_hash(password)
    };
    ntowf_v2_from_hash(&nt_hash, username, domain)
}

// ──────────────────────────────────────────────────────────────────────────────
// NTLM Version struct
// ──────────────────────────────────────────────────────────────────────────────

/// 8-byte NTLM Version field (optional but required when NEGOTIATE_VERSION is set).
/// We advertise Windows 10 / NTLM revision 15.
fn version_bytes() -> [u8; 8] {
    [0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f]
}

// ──────────────────────────────────────────────────────────────────────────────
// Type 1 — Negotiate Message
// ──────────────────────────────────────────────────────────────────────────────

/// Build the NTLM Negotiate (Type 1) message.
pub fn build_negotiate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(40);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&NTLMSSP_NEGOTIATE.to_le_bytes());
    msg.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());

    // DomainNameFields
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain len
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain max len
    msg.extend_from_slice(&40u32.to_le_bytes()); // domain offset

    // WorkstationFields
    msg.extend_from_slice(&0u16.to_le_bytes()); // workstation len
    msg.extend_from_slice(&0u16.to_le_bytes()); // workstation max len
    msg.extend_from_slice(&40u32.to_le_bytes()); // workstation offset

    // Version (8 bytes)
    msg.extend_from_slice(&version_bytes());
    msg
}

// ──────────────────────────────────────────────────────────────────────────────
// Type 2 — Challenge Message Parser
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed NTLM Challenge (Type 2) message.
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    pub target_name: Vec<u8>,
    pub negotiate_flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,          // raw AV_PAIR blob
    pub server_timestamp: Option<u64>, // from MsAvTimestamp if present
    pub domain_info: crate::rdp::DomainInfo,
}

/// Parse raw bytes of an NTLM Challenge message.
pub fn parse_challenge(data: &[u8]) -> Result<NtlmChallenge> {
    if data.len() < 56 {
        return Err(RdpError::Protocol("NTLM Challenge too short"));
    }
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(RdpError::Protocol("NTLM Challenge: bad signature"));
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if msg_type != NTLMSSP_CHALLENGE {
        return Err(RdpError::ProtocolMsg(format!(
            "NTLM: expected Type 2, got {msg_type}"
        )));
    }

    // TargetNameFields at offset 12
    let tn_len = u16::from_le_bytes(data[12..14].try_into().unwrap()) as usize;
    let tn_off = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

    let negotiate_flags = u32::from_le_bytes(data[20..24].try_into().unwrap());

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // Reserved [32..40] — skip

    // TargetInfoFields at offset 40
    let ti_len = u16::from_le_bytes(data[40..42].try_into().unwrap()) as usize;
    let ti_off = u32::from_le_bytes(data[44..48].try_into().unwrap()) as usize;

    let target_name = if tn_len > 0 && tn_off + tn_len <= data.len() {
        data[tn_off..tn_off + tn_len].to_vec()
    } else {
        Vec::new()
    };

    let target_info = if ti_len > 0 && ti_off + ti_len <= data.len() {
        data[ti_off..ti_off + ti_len].to_vec()
    } else {
        Vec::new()
    };

    // Extract MsAvTimestamp from target_info AV pairs if present
    let server_timestamp = extract_av_timestamp(&target_info);
    let mut domain_info = extract_domain_info(&target_info);

    // ── Parse NTLM Version field (bytes 48–55) ──────────────────────────────────
    // The Version struct is present when NTLMSSP_NEGOTIATE_VERSION flag is set.
    // Layout: [major:1][minor:1][build:2 LE][reserved:3][ntlm_rev:1]
    if (negotiate_flags & NTLMSSP_NEGOTIATE_VERSION) != 0 && data.len() >= 56 {
        let major = data[48];
        let minor = data[49];
        let build = u16::from_le_bytes([data[50], data[51]]);
        domain_info.os_version = Some(windows_version_string(major, minor, build));
    }

    tracing::debug!("NTLMv2: parsed Challenge (Type 2):");
    tracing::debug!("  - Server negotiate_flags: 0x{:08X}", negotiate_flags);
    tracing::debug!(
        "  - Server challenge: {:02x?}",
        server_challenge
    );
    tracing::debug!(
        "  - Target name: {:?}",
        String::from_utf8_lossy(&target_name)
    );
    tracing::debug!("  - Server timestamp (FILETIME): {:?}", server_timestamp);
    tracing::debug!("  - Target info length: {} bytes", target_info.len());
    if let Some(ref v) = domain_info.os_version {
        tracing::debug!("  - OS Version: {}", v);
    }

    Ok(NtlmChallenge {
        target_name,
        negotiate_flags,
        server_challenge,
        target_info,
        server_timestamp,
        domain_info,
    })
}

/// Extract MsAvTimestamp (AV_PAIR id 0x0007) from a TargetInfo blob.
fn extract_av_timestamp(target_info: &[u8]) -> Option<u64> {
    let mut pos = 0;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes(target_info[pos..pos + 2].try_into().ok()?);
        let av_len = u16::from_le_bytes(target_info[pos + 2..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if av_id == MS_AV_EOL {
            break;
        }
        if av_id == MS_AV_TIMESTAMP && av_len == 8 && pos + 8 <= target_info.len() {
            let ts = u64::from_le_bytes(target_info[pos..pos + 8].try_into().ok()?);
            return Some(ts);
        }
        pos += av_len;
    }
    None
}

/// Extract DomainInfo from a TargetInfo blob (AV_PAIRs).
pub fn extract_domain_info(target_info: &[u8]) -> crate::rdp::DomainInfo {
    let mut info = crate::rdp::DomainInfo::default();
    let mut pos = 0;
    while pos + 4 <= target_info.len() {
        let id = u16::from_le_bytes(target_info[pos..pos + 2].try_into().unwrap_or([0; 2]));
        let av_len =
            u16::from_le_bytes(target_info[pos + 2..pos + 4].try_into().unwrap_or([0; 2])) as usize;
        pos += 4;

        if id == MS_AV_EOL {
            break;
        }

        if pos + av_len <= target_info.len() {
            let data = &target_info[pos..pos + av_len];
            let decoded = String::from_utf16(
                &data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>(),
            )
            .unwrap_or_default();

            match id {
                MS_AV_NB_COMPUTER_NAME => info.computer_name = decoded,
                MS_AV_NB_DOMAIN_NAME => info.nb_domain = decoded,
                MS_AV_DNS_DOMAIN_NAME => info.dns_domain = decoded,
                MS_AV_DNS_TREE_NAME => info.dns_tree = decoded,
                _ => {}
            }
        }
        pos += av_len;
    }
    info
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows version helper
// ──────────────────────────────────────────────────────────────────────────────

/// Map NTLM challenge Version bytes (major, minor, build) to a human-readable string.
///
/// Build numbers from MS-NTLM / MSDN version history:
/// - 10.0.22000+ → Windows 11
/// - 10.0.19041+ → Windows 10 20H1 / Server 2019+
/// - 10.0.17763  → Windows 10 1809 / Server 2019
/// - 10.0.17134  → Windows 10 1803
/// - 10.0.16299  → Windows 10 1709
/// - 10.0.15063  → Windows 10 1703
/// - 10.0.14393  → Windows 10 1607 / Server 2016
/// - 10.0.10586  → Windows 10 1511
/// - 10.0.10240  → Windows 10 RTM
/// - 6.3.9600    → Windows 8.1 / Server 2012 R2
/// - 6.2.9200    → Windows 8 / Server 2012
/// - 6.1.7601    → Windows 7 SP1 / Server 2008 R2
/// - 6.1.7600    → Windows 7 RTM
/// - 6.0.6002    → Vista SP2 / Server 2008
/// - 5.2.3790    → Server 2003 / XP x64
/// - 5.1.2600    → Windows XP SP3
pub fn windows_version_string(major: u8, minor: u8, build: u16) -> String {
    let name = match (major, minor) {
        (10, 0) => match build {
            b if b >= 22000 => "Windows 11",
            b if b >= 20348 => "Server 2022",
            b if b >= 17763 => "Win10/Server 2019",
            b if b >= 14393 => "Win10/Server 2016",
            b if b >= 10240 => "Windows 10",
            _ => "Windows 10 (pre-release)",
        },
        (6, 3) => "Windows 8.1 / Server 2012 R2",
        (6, 2) => "Windows 8 / Server 2012",
        (6, 1) => "Windows 7 / Server 2008 R2",
        (6, 0) => "Windows Vista / Server 2008",
        (5, 2) => "Server 2003 / XP x64",
        (5, 1) => "Windows XP",
        _ => "Windows (unknown)",
    };
    format!("{} (build {})", name, build)
}

// ──────────────────────────────────────────────────────────────────────────────
// Type 3 — Authenticate Message Builder
// ──────────────────────────────────────────────────────────────────────────────

/// All keys and material derived during Type 3 construction.
#[derive(Debug)]
pub struct NtlmAuthResult {
    pub authenticate_message: Vec<u8>,
    pub exported_session_key: [u8; 16],
    pub session_base_key: [u8; 16],
}

/// Build the NTLM Authenticate (Type 3) message.
///
/// `negotiate_msg` and `challenge_msg` are the raw bytes of the Type 1 and Type 2
/// messages — needed for MIC computation.
pub fn build_authenticate(
    challenge: &NtlmChallenge,
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
    negotiate_msg: &[u8],
    challenge_msg: &[u8],
    precomputed_nt_hash: Option<[u8; 16]>,
) -> Result<NtlmAuthResult> {
    // mstsc/SSPI semantics: an empty domain (our "." placeholder) means "let the
    // server decide" — local SAM on member servers, real domain on DCs. Sending
    // a literal "." forces local-only validation and gets STATUS_LOGON_FAILURE
    // on DCs / domain accounts even with correct credentials.
    let domain = if domain == "." { "" } else { domain };

    let response_key_nt = match precomputed_nt_hash {
        Some(ref hash) => ntowf_v2_from_hash(hash, username, domain),
        None => ntowf_v2(password, username, domain),
    };

    // Client challenge: 8 random bytes
    let client_challenge = random_bytes_8();
    tracing::debug!(
        "NTLMv2: generated client challenge: {:02x?}",
        client_challenge
    );

    // Timestamp: use server timestamp if provided, otherwise current FILETIME
    let timestamp = challenge.server_timestamp.unwrap_or_else(filetime_now);
    tracing::debug!("NTLMv2: using timestamp: {}", timestamp);

    // Build NTLMv2 blob (temp value used in NtChallengeResponse)
    tracing::debug!(
        "NTLMv2: RAW TargetInfo from server: {:02x?}",
        challenge.target_info
    );
    let blob = build_ntlmv2_blob(timestamp, &client_challenge, &challenge.target_info);

    // NtProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || blob)
    let mut nt_proof_input = Vec::with_capacity(8 + blob.len());
    nt_proof_input.extend_from_slice(&challenge.server_challenge);
    nt_proof_input.extend_from_slice(&blob);
    let nt_proof_str = hmac_md5(&response_key_nt, &nt_proof_input);
    tracing::debug!("NTLMv2: calculated NtProofStr: {:02x?}", nt_proof_str);

    // NtChallengeResponse = NtProofStr || blob
    let mut nt_response = Vec::with_capacity(16 + blob.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // LmChallengeResponse — for NTLMv2 this is LmProofStr (8 zero bytes + client challenge)
    let lm_proof_str = {
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&challenge.server_challenge);
        input.extend_from_slice(&client_challenge);
        hmac_md5(&response_key_nt, &input)
    };
    let mut lm_response = Vec::with_capacity(24);
    lm_response.extend_from_slice(&lm_proof_str);
    lm_response.extend_from_slice(&client_challenge);

    // Flags — copy from server but ensure we keep our required flags
    let mut flags = challenge.negotiate_flags & NTLMSSP_NEGOTIATE_KEY_EXCH;
    if !domain.is_empty() {
        flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
    }
    flags |= NTLMSSP_NEGOTIATE_56
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION;
    if (NEGOTIATE_FLAGS & NTLMSSP_NEGOTIATE_SEAL) != 0 {
        flags |= NTLMSSP_NEGOTIATE_SEAL;
    }
    if (NEGOTIATE_FLAGS & NTLMSSP_NEGOTIATE_SIGN) != 0 {
        flags |= NTLMSSP_NEGOTIATE_SIGN;
    }
    tracing::debug!("NTLMv2: negotiated flags: 0x{:08X}", flags);

    // Session keys
    let session_base_key = hmac_md5(&response_key_nt, &nt_proof_str);
    tracing::debug!("NTLMv2: derived SessionBaseKey: {:02x?}", session_base_key);

    let key_exch = (flags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0;
    let (exported_session_key, encrypted_session_key) = if key_exch {
        let esk = random_bytes_16();
        let esk_enc = rc4_encrypt(&session_base_key, &esk);
        (esk, esk_enc)
    } else {
        (session_base_key, Vec::new())
    };
    tracing::debug!("NTLMv2: active session key: {:02x?}", exported_session_key);
    tracing::debug!(
        "NTLMv2: EncryptedRandomSessionKey: {:02x?}",
        encrypted_session_key
    );

    // Encode username, domain, workstation as UTF-16LE
    let username_bytes = unicode(username);
    let domain_bytes = unicode(domain);
    let workstation_bytes = unicode(workstation);

    // Fixed header size depends on NEGOTIATE_VERSION (same layout rule as the
    // proven rdp-rs client):
    //   base (72) + Version (8, only if NEGOTIATE_VERSION) + MIC (16)
    //   = 88 with version, 80 without.
    let base_offset: u32 = if (flags & NTLMSSP_NEGOTIATE_VERSION) != 0 {
        88
    } else {
        80
    };

    // Payload offsets, in payload write order:
    // 1. domain_name
    let domain_off = base_offset;
    // 2. user_name
    let user_off = domain_off + domain_bytes.len() as u32;
    // 3. workstation
    let ws_off = user_off + username_bytes.len() as u32;
    // 4. lm_challenge_response
    let lm_off = ws_off + workstation_bytes.len() as u32;
    // 5. nt_challenge_response
    let nt_off = lm_off + lm_response.len() as u32;
    // 6. encrypted_random_session_key
    let session_off = nt_off + nt_response.len() as u32;

    // Build the message (leave MIC as zeroes initially for MIC computation)
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&NTLMSSP_AUTH.to_le_bytes());

    // LmChallengeResponseFields
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&lm_off.to_le_bytes());

    // NtChallengeResponseFields
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    msg.extend_from_slice(&nt_off.to_le_bytes());

    // DomainNameFields
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_off.to_le_bytes());

    // UserNameFields
    msg.extend_from_slice(&(username_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(username_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&user_off.to_le_bytes());

    // WorkstationFields
    msg.extend_from_slice(&(workstation_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(workstation_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(&ws_off.to_le_bytes());

    // EncryptedRandomSessionKeyFields
    msg.extend_from_slice(&(encrypted_session_key.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(encrypted_session_key.len() as u16).to_le_bytes());
    msg.extend_from_slice(&session_off.to_le_bytes());

    // NegotiateFlags
    msg.extend_from_slice(&flags.to_le_bytes());

    // Version — only when NEGOTIATE_VERSION is set
    if (flags & NTLMSSP_NEGOTIATE_VERSION) != 0 {
        msg.extend_from_slice(&version_bytes());
    }

    // MIC placeholder — 16 zero bytes at this position
    let mic_offset = msg.len();
    msg.extend_from_slice(&[0u8; 16]);

    // Payload — order must match the offsets computed above
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&username_bytes);
    msg.extend_from_slice(&workstation_bytes);
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&encrypted_session_key);

    // Compute MIC = HMAC_MD5(ExportedSessionKey, Negotiate || Challenge || Authenticate_with_zero_MIC)
    let mut mic_input = Vec::with_capacity(negotiate_msg.len() + challenge_msg.len() + msg.len());
    mic_input.extend_from_slice(negotiate_msg);
    mic_input.extend_from_slice(challenge_msg);
    mic_input.extend_from_slice(&msg);
    let mic = hmac_md5(&exported_session_key, &mic_input);
    tracing::debug!(
        "NTLMv2: calculated MIC (Message Integrity Code): {:02x?}",
        mic
    );

    // Patch MIC into the message
    msg[mic_offset..mic_offset + 16].copy_from_slice(&mic);
    tracing::debug!(
        "NTLMv2: built final Authenticate (Type 3) message of {} bytes",
        msg.len()
    );

    Ok(NtlmAuthResult {
        authenticate_message: msg,
        exported_session_key,
        session_base_key,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// NTLMv2 blob (NtChallengeResponse variable portion)
// ──────────────────────────────────────────────────────────────────────────────

/// Build the blob appended after NtProofStr in NtChallengeResponse.
///
/// Structure (MS-NLMP §3.3.2):
///   RespType (1) | HiRespType (1) | Reserved1 (2) | Reserved2 (4)
///   | Timestamp (8) | ClientChallenge (8) | Reserved3 (4)
///   | TargetInfo (var) — EOL-stripped, then MsvAvFlags + MsvAvEOL
fn build_ntlmv2_blob(timestamp: u64, client_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    // Servers that verify the MIC (patched 2012 R2+) require MsvAvFlags=2
    // (MIC provided) in the echoed AV set — removing it gets the response
    // rejected on modern servers. Keep the AvFlags pair before the final EOL.
    let mut blob = Vec::with_capacity(28 + target_info.len() + 8);
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&[0x00, 0x00]); // Reserved1
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(client_challenge);
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved3
    blob.extend_from_slice(strip_av_eol(target_info));
    blob.extend_from_slice(&MS_AV_FLAGS.to_le_bytes());
    blob.extend_from_slice(&4u16.to_le_bytes());
    blob.extend_from_slice(&0x00000002u32.to_le_bytes()); // MIC provided
    blob.extend_from_slice(&MS_AV_EOL.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob
}

/// Strip the trailing MsAvEOL pair from a TargetInfo blob.
fn strip_av_eol(target_info: &[u8]) -> &[u8] {
    let mut pos = 0;
    let mut last_good_end = 0;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes(target_info[pos..pos + 2].try_into().unwrap_or([0; 2]));
        let av_len =
            u16::from_le_bytes(target_info[pos + 2..pos + 4].try_into().unwrap_or([0; 2])) as usize;
        if av_id == MS_AV_EOL {
            return &target_info[..pos];
        }
        last_good_end = pos + 4 + av_len;
        pos += 4 + av_len;
    }
    &target_info[..last_good_end]
}

// ──────────────────────────────────────────────────────────────────────────────
// RC4 encrypt (for EncryptedRandomSessionKey)
// ──────────────────────────────────────────────────────────────────────────────

fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    rc4_crypt(key, data)
}

// ──────────────────────────────────────────────────────────────────────────────
// Randomness (OS-seeded, no external rand crate)
// ──────────────────────────────────────────────────────────────────────────────

fn random_bytes_8() -> [u8; 8] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut out = [0u8; 8];
    SystemRandom::new().fill(&mut out).expect("random bytes");
    out
}

fn random_bytes_16() -> [u8; 16] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut out = [0u8; 16];
    SystemRandom::new().fill(&mut out).expect("random bytes");
    out
}

/// Current time as Windows FILETIME (100ns intervals since 1601-01-01).
fn filetime_now() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // UNIX epoch is 11644473600 seconds after the Windows FILETIME epoch (1601-01-01)
    let windows_secs = dur.as_secs() + 11_644_473_600u64;
    // Convert to 100ns intervals and include sub-second nanoseconds
    windows_secs * 10_000_000 + (dur.subsec_nanos() as u64 / 100)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from MS-NLMP Appendix B
    #[test]
    fn md4_known_vector() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        let hash = md4(b"");
        let expected = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn md4_abc() {
        // MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        let hash = md4(b"abc");
        let expected = [
            0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6,
            0x72, 0x9d,
        ];
        assert_eq!(hash, expected);
    }

    /// MS-NLMP Appendix B.1 — NTOWFv2 test vector
    /// User = "User", Password = "Password", Domain = "Domain"
    /// ResponseKeyNT = 75377f3018d3a20b23cb31bda1185a41 (from appendix)
    #[test]
    fn ntowf_v2_test_vector() {
        let response_key = ntowf_v2("Password", "User", "Domain");
        // Expected NTLM v2 hash (HMAC-MD5) for "password" + "domain" + "user"
        const EXPECTED_NTOWF_V2: [u8; 16] = [
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
            0x2e, 0x3f,
        ];
        assert_eq!(response_key, EXPECTED_NTOWF_V2);
    }

    #[test]
    fn negotiate_message_signature() {
        let msg = build_negotiate();
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, NTLMSSP_NEGOTIATE);
    }

    #[test]
    fn unicode_password() {
        let w = unicode("Password");
        assert_eq!(w.len(), 16); // 8 chars × 2 bytes
        assert_eq!(w[0], b'P');
        assert_eq!(w[1], 0x00);
    }
}

pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    let utf16_count = password.encode_utf16().count();
    if utf16_count <= 27 {
        let mut block = [0u8; 64];
        let mut byte_idx = 0;
        for c in password.encode_utf16() {
            let bytes = c.to_le_bytes();
            block[byte_idx] = bytes[0];
            block[byte_idx + 1] = bytes[1];
            byte_idx += 2;
        }
        block[byte_idx] = 0x80;
        let bit_len = (byte_idx as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_le_bytes());

        let mut x = [0u32; 16];
        for i in 0..16 {
            let b0 = block[i * 4] as u32;
            let b1 = block[i * 4 + 1] as u32;
            let b2 = block[i * 4 + 2] as u32;
            let b3 = block[i * 4 + 3] as u32;
            x[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        fast_md4_block(&x)
    } else {
        let pw_utf16 = unicode(password);
        md4(&pw_utf16)
    }
}
