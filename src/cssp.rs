/// CredSSP (MS-CSSP) — Credential Security Support Provider Protocol
///
/// Drives the 5-message NLA handshake over TLS:
///
///   Client → Server: TSRequest { negoTokens: [SPNEGO(NtlmNegotiate)] }
///   Server → Client: TSRequest { negoTokens: [SPNEGO(NtlmChallenge)] }
///   Client → Server: TSRequest { negoTokens: [SPNEGO(NtlmAuth)], pubKeyAuth: ... }
///   Server → Client: TSRequest { pubKeyAuth: ... } (optional validation)
///   Client → Server: TSRequest { authInfo: TSCredentials }
///
/// Reference: MS-CSSP §3.1.5
///
/// TSRequest ASN.1 (DER):
///   TSRequest ::= SEQUENCE {
///     version    [0] INTEGER,
///     negoTokens [1] NegoData OPTIONAL,
///     authInfo   [2] OCTET STRING OPTIONAL,
///     pubKeyAuth [3] OCTET STRING OPTIONAL,
///     errorCode  [4] INTEGER OPTIONAL,
///     clientNonce[5] OCTET STRING OPTIONAL
///   }
use crate::asn1::{
    ctx, expect_tag, read_integer, read_tlv, wrap_ctx, wrap_sequence, write_integer_u32,
    write_octet_string, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::error::{RdpError, Result};
use crate::ntlm::{build_authenticate, build_negotiate, parse_challenge};
use crate::spnego::extract_ntlm_from_spnego;

use hmac::{Hmac, Mac};
use md5::Md5;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type HmacMd5 = Hmac<Md5>;

// Inline RC4 — avoids generic_array type-parameter ambiguity from the rc4 crate
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

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// TSRequest encoder/decoder
// ──────────────────────────────────────────────────────────────────────────────

const CREDSSP_VERSION: u32 = 6; // CredSSP v6

/// TSRequest fields we need to build or parse.
#[derive(Debug, Default)]
pub struct TsRequest {
    pub version: u32,
    pub nego_tokens: Option<Vec<u8>>, // raw SPNEGO token bytes
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<i64>,
    pub client_nonce: Option<Vec<u8>>,
}

/// Encode a TSRequest into DER bytes ready to be sent over TLS.
pub fn encode_ts_request(req: &TsRequest) -> Vec<u8> {
    let mut inner = Vec::new();

    // [0] version
    let mut ver = Vec::new();
    write_integer_u32(req.version, &mut ver);
    wrap_ctx(0, &ver, &mut inner);

    // [1] negoTokens — NegoData ::= SEQUENCE OF NegoDataItem
    //     NegoDataItem ::= SEQUENCE { negoToken [0] OCTET STRING }
    if let Some(token) = &req.nego_tokens {
        let mut oct = Vec::new();
        write_octet_string(token, &mut oct);

        let mut nego_item_inner = Vec::new();
        wrap_ctx(0, &oct, &mut nego_item_inner); // [0] negoToken

        let mut nego_item = Vec::new();
        wrap_sequence(&nego_item_inner, &mut nego_item);

        let mut nego_data = Vec::new();
        wrap_sequence(&nego_item, &mut nego_data); // SEQUENCE OF NegoDataItem

        wrap_ctx(1, &nego_data, &mut inner);
    }

    // [2] authInfo
    if let Some(auth) = &req.auth_info {
        let mut oct = Vec::new();
        write_octet_string(auth, &mut oct);
        wrap_ctx(2, &oct, &mut inner);
    }

    // [3] pubKeyAuth
    if let Some(pka) = &req.pub_key_auth {
        let mut oct = Vec::new();
        write_octet_string(pka, &mut oct);
        wrap_ctx(3, &oct, &mut inner);
    }

    // [4] errorCode
    if let Some(err) = req.error_code {
        let mut err_val = Vec::new();
        // Encode i64 integer correctly (including negative values)
        let bytes = if (-128..=127).contains(&err) {
            vec![err as u8]
        } else if (-32768..=32767).contains(&err) {
            vec![(err >> 8) as u8, (err & 0xFF) as u8]
        } else if (-8388608..=8388607).contains(&err) {
            vec![(err >> 16) as u8, (err >> 8) as u8, (err & 0xFF) as u8]
        } else if (-2147483648..=2147483647).contains(&err) {
            let b = (err as i32).to_be_bytes();
            b.to_vec()
        } else {
            let b = err.to_be_bytes();
            b.to_vec()
        };
        crate::asn1::write_tlv(0x02, &bytes, &mut err_val);
        wrap_ctx(4, &err_val, &mut inner);
    }

    // [5] clientNonce
    if let Some(cn) = &req.client_nonce {
        let mut oct = Vec::new();
        write_octet_string(cn, &mut oct);
        wrap_ctx(5, &oct, &mut inner);
    }

    let mut seq = Vec::new();
    wrap_sequence(&inner, &mut seq);
    seq
}

/// Decode a TSRequest from DER bytes.
pub fn decode_ts_request(data: &[u8]) -> Result<TsRequest> {
    let (seq_val, _) = expect_tag(data, 0, TAG_SEQUENCE)?;
    let mut req = TsRequest::default();
    let mut pos = 0;

    while pos < seq_val.len() {
        let (tag, val, next) = read_tlv(seq_val, pos)?;
        match tag {
            t if t == ctx(0) => {
                // version
                let (ver, _) = read_integer(val, 0)?;
                req.version = ver as u32;
            }
            t if t == ctx(1) => {
                // negoTokens: SEQUENCE OF { SEQUENCE { [0] OCTET STRING } }
                req.nego_tokens = Some(extract_nego_token(val)?);
            }
            t if t == ctx(2) => {
                let (oct, _) = expect_tag(val, 0, TAG_OCTET_STRING)?;
                req.auth_info = Some(oct.to_vec());
            }
            t if t == ctx(3) => {
                let (oct, _) = expect_tag(val, 0, TAG_OCTET_STRING)?;
                req.pub_key_auth = Some(oct.to_vec());
            }
            t if t == ctx(4) => {
                let (code, _) = read_integer(val, 0)?;
                req.error_code = Some(code);
            }
            t if t == ctx(5) => {
                let (oct, _) = expect_tag(val, 0, TAG_OCTET_STRING)?;
                req.client_nonce = Some(oct.to_vec());
            }
            _ => { /* unknown field — skip */ }
        }
        pos = next;
    }

    Ok(req)
}

fn extract_nego_token(nego_data_val: &[u8]) -> Result<Vec<u8>> {
    // nego_data_val is the value of [1], which contains:
    // SEQUENCE OF { SEQUENCE { [0] OCTET STRING } }
    let (outer_seq, _) = expect_tag(nego_data_val, 0, TAG_SEQUENCE)?;
    let (item_seq, _) = expect_tag(outer_seq, 0, TAG_SEQUENCE)?;
    let (ctx0_val, _) = expect_tag(item_seq, 0, ctx(0))?;
    let (oct, _) = expect_tag(ctx0_val, 0, TAG_OCTET_STRING)?;
    Ok(oct.to_vec())
}

// ──────────────────────────────────────────────────────────────────────────────
// TSCredentials encoder
// ──────────────────────────────────────────────────────────────────────────────

/// TSCredentials ::= SEQUENCE {
///   credType [0] INTEGER,   -- 1 = password
///   credentials [1] OCTET STRING  -- TSPasswordCreds DER bytes
/// }
///
/// TSPasswordCreds ::= SEQUENCE {
///   domainName  [0] OCTET STRING (UTF-16LE),
///   userName    [1] OCTET STRING (UTF-16LE),
///   password    [2] OCTET STRING (UTF-16LE)
/// }
pub fn encode_ts_credentials(domain: &str, username: &str, password: &str) -> Vec<u8> {
    use crate::ntlm::unicode;

    // TSPasswordCreds
    let mut pw_creds_inner = Vec::new();

    let domain_utf16 = unicode(domain);
    let mut dom_oct = Vec::new();
    write_octet_string(&domain_utf16, &mut dom_oct);
    wrap_ctx(0, &dom_oct, &mut pw_creds_inner);

    let user_utf16 = unicode(username);
    let mut user_oct = Vec::new();
    write_octet_string(&user_utf16, &mut user_oct);
    wrap_ctx(1, &user_oct, &mut pw_creds_inner);

    let pass_utf16 = unicode(password);
    let mut pass_oct = Vec::new();
    write_octet_string(&pass_utf16, &mut pass_oct);
    wrap_ctx(2, &pass_oct, &mut pw_creds_inner);

    let mut pw_creds = Vec::new();
    wrap_sequence(&pw_creds_inner, &mut pw_creds);

    // TSCredentials
    let mut ts_creds_inner = Vec::new();

    let mut cred_type = Vec::new();
    write_integer_u32(1, &mut cred_type); // 1 = password
    wrap_ctx(0, &cred_type, &mut ts_creds_inner);

    let mut creds_oct = Vec::new();
    write_octet_string(&pw_creds, &mut creds_oct);
    wrap_ctx(1, &creds_oct, &mut ts_creds_inner);

    let mut ts_creds = Vec::new();
    wrap_sequence(&ts_creds_inner, &mut ts_creds);
    ts_creds
}

// ──────────────────────────────────────────────────────────────────────────────
// CredSSP Authentication Result
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AuthResult {
    pub success: bool,
    pub reason: Option<String>,
    pub domain_info: Option<crate::rdp::DomainInfo>,
    pub ntstatus: Option<u32>,
}

pub fn parse_ntstatus(code: u32, domain_info: Option<crate::rdp::DomainInfo>) -> AuthResult {
    let res = match code {

        // ── Genuine success ───────────────────────────────────────────────────
        0x00000000 => AuthResult {
            success: true,
            reason: Some("STATUS_SUCCESS".into()),
            domain_info, ntstatus: Some(code),
        },
        // Internal sentinel used by our engine when server RSTs after step-3
        0xC0000000 => AuthResult {
            success: true,
            reason: Some("STATUS_SUCCESS (connection-reset sentinel)".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Password correct but account/policy restricts full logon ─────────
        // These are SAVES — the credential is valid, just the account has a condition.
        0xC0000022 => AuthResult {
            success: false,
            reason: Some("STATUS_ACCESS_DENIED — no RDP rights".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000071 | 0x1207 => AuthResult {
            success: false,
            reason: Some("STATUS_PASSWORD_EXPIRED — password expired, must change".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000224 => AuthResult {
            success: false,
            reason: Some("STATUS_PASSWORD_MUST_CHANGE — must change password at next logon".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000006E | 0x1307 => AuthResult {
            success: false,
            reason: Some("STATUS_ACCOUNT_RESTRICTION — logon hours or workstation restriction".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000193 | 0xC0000133 => AuthResult {
            success: false,
            reason: Some("STATUS_ACCOUNT_EXPIRED — account has expired".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000015B => AuthResult {
            success: false,
            reason: Some("STATUS_LOGON_TYPE_NOT_GRANTED — RDP logon type not granted".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000070 => AuthResult {
            success: false,
            reason: Some("STATUS_WORKSTATION_RESTRICTION — not allowed on this workstation".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000006F => AuthResult {
            success: false,
            reason: Some("STATUS_INVALID_LOGON_HOURS — outside authorized logon hours".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000234 => AuthResult {
            success: false,
            reason: Some("STATUS_ACCOUNT_LOCKED_OUT — account locked (too many failed attempts)".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000072 => AuthResult {
            success: false,
            reason: Some("STATUS_ACCOUNT_DISABLED — account is disabled".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000005E => AuthResult {
            success: false,
            reason: Some("STATUS_NO_LOGON_SERVERS — no domain controllers available".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Wrong password / bad credentials ──────────────────────────────────
        0xC000006D => AuthResult {
            success: false,
            reason: Some("STATUS_LOGON_FAILURE — wrong username or password".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000006A => AuthResult {
            success: false,
            reason: Some("STATUS_WRONG_PASSWORD — correct username, wrong password".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000064 => AuthResult {
            success: false,
            reason: Some("STATUS_NO_SUCH_USER — username does not exist".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000062 => AuthResult {
            success: false,
            reason: Some("STATUS_NO_SUCH_DOMAIN — domain does not exist".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000009A => AuthResult {
            success: false,
            reason: Some("STATUS_INSUFFICIENT_RESOURCES — server out of resources".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── SmartCard / Certificate required ─────────────────────────────────
        // Password is correct but SmartCard policy blocks password-only auth.
        0xC0000320 => AuthResult {
            success: false,
            reason: Some("STATUS_SMARTCARD_WRONG_PIN — smart card required".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000361 => AuthResult {
            success: false,
            reason: Some("STATUS_SMARTCARD_SUBSYSTEM_FAILURE — smart card subsystem failure".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000035C => AuthResult {
            success: false,
            reason: Some("STATUS_SMARTCARD_NO_CARD — smart card required, not inserted".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000386 => AuthResult {
            success: false,
            reason: Some("STATUS_SMARTCARD_CERT_EXPIRED — smart card certificate expired".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000346 => AuthResult {
            success: false,
            reason: Some("STATUS_SMARTCARD_LOGON_REQUIRED — smart card logon required, password not accepted".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Domain / Kerberos / DC errors ─────────────────────────────────────
        0xC000009B => AuthResult {
            success: false,
            reason: Some("STATUS_NO_LOGON_SERVERS — no domain controllers reachable".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000018D => AuthResult {
            success: false,
            reason: Some("STATUS_TRUSTED_RELATIONSHIP_FAILURE — trust relationship broken".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000190 => AuthResult {
            success: false,
            reason: Some("STATUS_NO_TRUST_SAM_ACCOUNT — no trust SAM account".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000191 => AuthResult {
            success: false,
            reason: Some("STATUS_TRUSTED_DOMAIN_FAILURE — trusted domain failure".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000192 => AuthResult {
            success: false,
            reason: Some("STATUS_TRUST_FAILURE — network logon failed (trust failure)".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000006B => AuthResult {
            success: false,
            reason: Some("STATUS_PASSWORD_TOO_SHORT — password does not meet minimum length".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000006C => AuthResult {
            success: false,
            reason: Some("STATUS_PASSWORD_TOO_RECENT — password changed too recently".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000007F => AuthResult {
            success: false,
            reason: Some("STATUS_DISK_FULL — server disk full (infrastructure error)".into()),
            domain_info, ntstatus: Some(code),
        },
        0x80090302 => AuthResult {
            success: false,
            reason: Some("SEC_E_UNSUPPORTED_FUNCTION — CredSSP function not supported".into()),
            domain_info, ntstatus: Some(code),
        },
        0x80090303 => AuthResult {
            success: false,
            reason: Some("SEC_E_TARGET_UNKNOWN — target server unknown".into()),
            domain_info, ntstatus: Some(code),
        },
        0x80090304 => AuthResult {
            success: false,
            reason: Some("SEC_E_INTERNAL_ERROR — internal CredSSP error".into()),
            domain_info, ntstatus: Some(code),
        },
        0x80090308 => AuthResult {
            success: false,
            reason: Some("SEC_E_INVALID_TOKEN — invalid CredSSP token".into()),
            domain_info, ntstatus: Some(code),
        },
        0x8009030C => AuthResult {
            success: false,
            reason: Some("SEC_E_NO_CREDENTIALS — no credentials available for CredSSP".into()),
            domain_info, ntstatus: Some(code),
        },
        0x80090311 => AuthResult {
            success: false,
            reason: Some("SEC_E_NO_AUTHENTICATING_AUTHORITY — no DC to authenticate against".into()),
            domain_info, ntstatus: Some(code),
        },
        0x8009031B => AuthResult {
            success: false,
            reason: Some("SEC_E_LOGON_DENIED — CredSSP logon denied".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Security / policy infrastructure ─────────────────────────────────
        0xC0000413 => AuthResult {
            success: false,
            reason: Some("STATUS_AUTHENTICATION_FIREWALL_FAILED — NLA auth blocked by firewall policy".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000388 => AuthResult {
            success: false,
            reason: Some("STATUS_DOWNGRADE_DETECTED — NTLM downgrade attack detected".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC0000121 => AuthResult {
            success: false,
            reason: Some("STATUS_CANNOT_DELETE — cannot complete auth operation".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC00000BB => AuthResult {
            success: false,
            reason: Some("STATUS_NOT_SUPPORTED — auth method not supported by server".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC000007C => AuthResult {
            success: false,
            reason: Some("STATUS_NO_TOKEN — no impersonation token (NLA session issue)".into()),
            domain_info, ntstatus: Some(code),
        },
        0xC00002EE => AuthResult {
            success: false,
            reason: Some("STATUS_UNSUCCESSFUL — generic failure (server-side error)".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Win32 RDP-specific error codes (sent in errorCode field) ──────────
        // These appear in the CredSSP errorCode ASN.1 field from the RDP server.
        0x00000005 => AuthResult {
            success: false,
            reason: Some("Win32:ERROR_ACCESS_DENIED — RDP access not granted".into()),
            domain_info, ntstatus: Some(code),
        },
        0x00000043 => AuthResult {
            success: false,
            reason: Some("Win32:ERROR_BAD_NET_NAME — network path not found".into()),
            domain_info, ntstatus: Some(code),
        },
        0x00000047 => AuthResult {
            success: false,
            reason: Some("Win32:ERROR_NOT_ENOUGH_MEMORY — server out of memory".into()),
            domain_info, ntstatus: Some(code),
        },

        // ── Catch-all for unknown codes ───────────────────────────────────────
        _ => AuthResult {
            success: false,
            reason: Some(format!("NTSTATUS 0x{:08X} (unknown — treat as invalid)", code)),
            domain_info,
            ntstatus: Some(code),
        },
    };
    res
}

/// Returns true if the NTSTATUS code indicates the account is locked out.
/// Callers should skip re-authentication (honeypot check, rdp-rs validator)
/// to avoid worsening the lockout.
pub fn ntstatus_is_locked(code: u32) -> bool {
    code == 0xC0000234
}

/// Returns true if the NTSTATUS indicates the password is valid but something
/// else is wrong (expired, locked, restricted, no RDP rights, smartcard, etc.)
/// — the credential SHOULD be saved.
pub fn ntstatus_is_valid_credential(code: u32) -> bool {
    matches!(code,
        0x00000000  // STATUS_SUCCESS
        | 0xC0000000  // sentinel
        | 0xC0000022  // ACCESS_DENIED (no RDP rights)
        | 0xC0000071 | 0x1207  // PASSWORD_EXPIRED
        | 0xC0000224  // PASSWORD_MUST_CHANGE
        | 0xC000006E | 0x1307  // ACCOUNT_RESTRICTION
        | 0xC0000193 | 0xC0000133  // ACCOUNT_EXPIRED
        | 0xC000015B  // LOGON_TYPE_NOT_GRANTED
        | 0xC0000070  // WORKSTATION_RESTRICTION
        | 0xC000006F  // INVALID_LOGON_HOURS
        | 0xC0000234  // ACCOUNT_LOCKED_OUT
        | 0xC0000320  // SMARTCARD_WRONG_PIN
        | 0xC0000361  // SMARTCARD_SUBSYSTEM_FAILURE
        | 0xC000035C  // SMARTCARD_NO_CARD
        | 0xC0000386  // SMARTCARD_CERT_EXPIRED
        | 0x00000005  // Win32 ACCESS_DENIED
    )
}


// ──────────────────────────────────────────────────────────────────────────────
// CredSSP state machine
// ──────────────────────────────────────────────────────────────────────────────

fn random_bytes_32() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut nonce = [0u8; 32];
    SystemRandom::new().fill(&mut nonce).expect("random bytes");
    nonce
}

fn ntlm_wrap(
    exported_session_key: &[u8],
    message: &[u8],
    client_nonce: &[u8],
    credssp_version: u32,
) -> Vec<u8> {
    use md5::{Digest, Md5};
    use sha2::{Digest as Sha256Digest, Sha256};

    // 1. Derive ClientSigningKey and ClientSealingKey
    let client_signing_key = {
        let mut hasher = Md5::new();
        hasher.update(exported_session_key);
        hasher.update(b"session key to client-to-server signing key magic constant\0");
        hasher.finalize()
    };
    let client_sealing_key = {
        let mut hasher = Md5::new();
        hasher.update(exported_session_key);
        hasher.update(b"session key to client-to-server sealing key magic constant\0");
        hasher.finalize()
    };

    tracing::debug!(
        "NTLMv2 wrap: ClientSigningKey: {:02x?}",
        client_signing_key.as_slice()
    );
    tracing::debug!(
        "NTLMv2 wrap: ClientSealingKey: {:02x?}",
        client_sealing_key.as_slice()
    );

    // 1.5 Bind the public key (CredSSP version-dependent, MS-CSSP §3.1.5.2.1
    // and sspi-rs reference behavior):
    //   - peer v5+: SHA-256("CredSSP Client-To-Server Binding Hash\0" || clientNonce || SPKI)
    //   - peer v2-v4: NO hash — the SPKI bytes themselves are sealed (echo).
    //     (An MD5-based variant is sometimes claimed but does NOT match the
    //     reference implementation nor real Windows clients.)
    let payload: Vec<u8> = if credssp_version >= 5 {
        let hash_magic = b"CredSSP Client-To-Server Binding Hash\0";
        let mut data_to_hash = Vec::new();
        data_to_hash.extend_from_slice(hash_magic);
        data_to_hash.extend_from_slice(client_nonce);
        data_to_hash.extend_from_slice(message);

        let mut hasher = Sha256::new();
        hasher.update(&data_to_hash);
        hasher.finalize().to_vec()
    } else {
        message.to_vec()
    };

    // 2. Setup RC4 state
    struct Rc4State {
        s: [u8; 256],
        i: usize,
        j: usize,
    }
    impl Rc4State {
        fn new(key: &[u8]) -> Self {
            let mut s = [0u8; 256];
            for (i, v) in s.iter_mut().enumerate() {
                *v = i as u8;
            }
            let mut j = 0usize;
            for i in 0..256 {
                j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
                s.swap(i, j);
            }
            Self { s, i: 0, j: 0 }
        }
        fn crypt(&mut self, data: &mut [u8]) {
            for byte in data.iter_mut() {
                self.i = (self.i + 1) % 256;
                self.j = (self.j + self.s[self.i] as usize) % 256;
                self.s.swap(self.i, self.j);
                *byte ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) % 256];
            }
        }
    }

    let mut rc4 = Rc4State::new(&client_sealing_key);

    // 3. Encrypt the message payload
    let mut encrypted_message = payload.clone();
    rc4.crypt(&mut encrypted_message);
    tracing::debug!("NTLMv2 wrap: plaintext message: {:02x?}", payload);
    tracing::debug!("NTLMv2 wrap: encrypted message: {:02x?}", encrypted_message);

    // 4. Calculate Checksum = HMAC_MD5(ClientSigningKey, SeqNum(4 bytes) || Message(plaintext))
    let seq_num = 0u32;
    let mut mac_input = Vec::with_capacity(4 + payload.len());
    mac_input.extend_from_slice(&seq_num.to_le_bytes());
    mac_input.extend_from_slice(&payload);

    let checksum_full = hmac_md5(&client_signing_key, &mac_input);
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&checksum_full[0..8]);
    tracing::debug!("NTLMv2 wrap: plaintext checksum: {:02x?}", checksum);

    // 5. Encrypt Checksum
    // The RC4 state is CONTINUOUS. We encrypt the checksum with the same state.
    rc4.crypt(&mut checksum);
    tracing::debug!("NTLMv2 wrap: encrypted checksum: {:02x?}", checksum);

    // 6. Build NTLMSSP_MESSAGE_SIGNATURE
    let mut signature = [0u8; 16];
    signature[0..4].copy_from_slice(&1u32.to_le_bytes()); // Version = 1
    signature[4..12].copy_from_slice(&checksum); // Encrypted Checksum
    signature[12..16].copy_from_slice(&seq_num.to_le_bytes()); // SeqNum = 0

    let mut out = Vec::with_capacity(16 + encrypted_message.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&encrypted_message);
    out
}

/// Run the full CredSSP / NTLMv2 authentication handshake over a TLS stream.
///
/// Returns `AuthResult` indicating success or failure with a reason.
pub async fn run_credssp<S>(
    stream: &mut S,
    username: &str,
    password: &str,
    domain: &str,
    server_pubkey: &[u8],
    precomputed_nt_hash: Option<[u8; 16]>,
) -> Result<AuthResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate 32-byte clientNonce
    let client_nonce = random_bytes_32();

    // ── Step 1: Send raw NTLM Negotiate ────────────────────────────
    let negotiate_raw = build_negotiate();

    let req1 = TsRequest {
        version: CREDSSP_VERSION,
        nego_tokens: Some(negotiate_raw.clone()),
        client_nonce: Some(client_nonce.to_vec()),
        ..Default::default()
    };
    send_ts_request(stream, &req1).await?;
    tracing::debug!("CredSSP: sent TSRequest 1 (NTLM Negotiate)");

    // ── Step 2: Receive NTLM Challenge ────────────────────────────────────────
    let resp1 = recv_ts_request(stream).await?;

    // CredSSP: the TSRequest version field keeps OUR max version (6) in every
    // message — matching sspi-rs and mstsc. Only the pubKeyAuth *format* adapts
    // to the peer's version (echo of SPKI for v2-v4, SHA-256+nonce for v5+).
    let credssp_ver = if (2..=6).contains(&resp1.version) {
        resp1.version
    } else {
        CREDSSP_VERSION
    };
    tracing::debug!("CredSSP: peer protocol version {credssp_ver} (we keep sending v{CREDSSP_VERSION})");

    if let Some(code) = resp1.error_code {
        return Ok(AuthResult {
            domain_info: None,
            success: false,
            reason: Some(format!("Server returned error code: 0x{code:08X}")),
            ntstatus: Some(code as u32),
        });
    }

    let nego_token = resp1
        .nego_tokens
        .ok_or_else(|| RdpError::Protocol("CredSSP: server TSRequest 2 missing negoTokens"))?;

    // Support both SPNEGO-wrapped and raw NTLM Challenge
    let challenge_raw = if nego_token.starts_with(b"NTLMSSP\0") {
        nego_token.clone()
    } else {
        extract_ntlm_from_spnego(&nego_token)?
    };

    let challenge = parse_challenge(&challenge_raw)?;
    tracing::debug!("CredSSP: received NTLM Challenge");

    // ── Step 3: Build NTLM Authenticate + pubKeyAuth ──────────────────────────
    let workstation = "";
    let auth_result = build_authenticate(
        &challenge,
        username,
        password,
        domain,
        workstation,
        &negotiate_raw,
        &challenge_raw,
        precomputed_nt_hash,
    )?;

    // Send raw NTLM Authenticate (no SPNEGO)
    let nego_tokens_to_send = auth_result.authenticate_message.clone();

    // Try wrapping the full SPKI instead of the raw_pubkey
    let pub_key_auth = ntlm_wrap(
        &auth_result.exported_session_key,
        server_pubkey,
        &client_nonce,
        credssp_ver,
    );
    tracing::debug!(
        "CredSSP: pub_key_auth (NTLM wrapped) len = {}",
        pub_key_auth.len()
    );

    let req2 = TsRequest {
        version: CREDSSP_VERSION,
        nego_tokens: Some(nego_tokens_to_send),
        pub_key_auth: Some(pub_key_auth),
        client_nonce: Some(client_nonce.to_vec()),
        ..Default::default()
    };
    send_ts_request(stream, &req2).await?;
    tracing::debug!("CredSSP: sent TSRequest 3 (NTLM Authenticate + pubKeyAuth)");

    // ── Step 4: Receive server pubKeyAuth confirmation ────────────────────────
    let resp2 = match recv_ts_request(stream).await {
        Ok(r) => r,
        Err(e) => {
            // If server closed/RST connection right after receiving NTLM Authenticate (Step 3),
            // Windows RDP is rejecting the credentials (STATUS_LOGON_FAILURE / 0xC000006D).
            // Treating this as Invalid rather than Error avoids Throttling/Retrying.
            tracing::debug!("CredSSP: connection reset after NTLM auth (invalid credentials): {:?}", e);
            return Ok(parse_ntstatus(
                0xC000006D,
                Some(challenge.domain_info.clone()),
            ));
        }
    };

    if let Some(code) = resp2.error_code {
        return Ok(parse_ntstatus(
            code as u32,
            Some(challenge.domain_info.clone()),
        ));
    }

    // Verify server's pubKeyAuth (it should be our key + 1 incremented, or matching)
    // For credential checking purposes, if we got here without an error code, auth succeeded
    if resp2.pub_key_auth.is_none() && resp2.error_code.is_none() {
        // Some servers skip step 4 — treat as success
        tracing::debug!("CredSSP: server skipped pubKeyAuth confirmation");
    }
    tracing::debug!("CredSSP: received server pubKeyAuth confirmation");

    // ── Step 5: Send TSCredentials ────────────────────────────────────────────
    let ts_creds = encode_ts_credentials(domain, username, password);

    // Encrypt TSCredentials using RC4 with ExportedSessionKey
    let encrypted_creds = rc4_seal(&auth_result.exported_session_key, &ts_creds);

    let req3 = TsRequest {
        version: CREDSSP_VERSION,
        auth_info: Some(encrypted_creds),
        ..Default::default()
    };
    send_ts_request(stream, &req3).await?;
    tracing::debug!("CredSSP: sent TSRequest 5 (TSCredentials)");

    // ── Wait for final server response or clean close ─────────────────────────
    // If the server rejects the credentials (e.g. Logon failure), it will send a TSRequest with an error_code before closing.
    // If it accepts them, it usually just closes the CredSSP TLS stream and waits for RDP MCS connect.
    let final_res = recv_ts_request(stream).await;
    match final_res {
        Ok(resp3) => {
            if let Some(code) = resp3.error_code {
                return Ok(parse_ntstatus(code as u32, Some(challenge.domain_info)));
            }
            // Got a valid TSRequest without an error code, treat as success
            Ok(AuthResult {
                domain_info: Some(challenge.domain_info),
                success: true,
                reason: None,
                ntstatus: Some(0xC0000000), // STATUS_SUCCESS
            })
        }
        Err(e) => {
            // Connection closed or EOF is EXPECTED on success in some RDP versions
            tracing::debug!("CredSSP: connection closed or error reading final response (expected on success): {:?}", e);
            Ok(AuthResult {
                domain_info: Some(challenge.domain_info),
                success: true,
                reason: None,
                ntstatus: Some(0xC0000000),
            })
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RC4 sealing
// ──────────────────────────────────────────────────────────────────────────────

fn rc4_seal(key: &[u8], data: &[u8]) -> Vec<u8> {
    rc4_crypt(key, data)
}

// ──────────────────────────────────────────────────────────────────────────────
// TSRequest framing over TLS
// ──────────────────────────────────────────────────────────────────────────────

/// Send a TSRequest over the TLS stream (length-prefixed by the DER SEQUENCE itself).
async fn send_ts_request<S: AsyncWrite + Unpin>(stream: &mut S, req: &TsRequest) -> Result<()> {
    tracing::debug!(
        "CredSSP: sending TSRequest (version={}, nego_tokens_len={:?}, auth_info_len={:?}, pub_key_auth_len={:?})",
        req.version,
        req.nego_tokens.as_ref().map(|v| v.len()),
        req.auth_info.as_ref().map(|v| v.len()),
        req.pub_key_auth.as_ref().map(|v| v.len())
    );
    let encoded = encode_ts_request(req);
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive and decode a TSRequest from the TLS stream.
///
/// TSRequest is self-delimiting DER, so we read the SEQUENCE header first,
/// determine its length, then read the rest.
async fn recv_ts_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<TsRequest> {
    // Read tag + at least 1 byte of length
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != TAG_SEQUENCE {
        return Err(RdpError::ProtocolMsg(format!(
            "CredSSP: expected SEQUENCE (0x30), got 0x{:02X}",
            header[0]
        )));
    }

    // Determine total length
    let (total_len, extra_header) = if header[1] < 0x80 {
        (header[1] as usize, 0)
    } else {
        let extra = (header[1] & 0x7F) as usize;
        if extra > 4 {
            return Err(RdpError::Protocol("CredSSP: oversized TSRequest length"));
        }
        let mut lb = vec![0u8; extra];
        stream.read_exact(&mut lb).await?;
        let mut len = 0usize;
        for b in &lb {
            len = (len << 8) | (*b as usize);
        }
        (len, extra)
    };

    // Read the value
    let mut value = vec![0u8; total_len];
    stream.read_exact(&mut value).await?;

    // Reconstruct the full DER for the decoder
    let decoded = if extra_header > 0 {
        let mut rebuilt = Vec::new();
        use crate::asn1::encode_len;
        rebuilt.push(TAG_SEQUENCE);
        encode_len(total_len, &mut rebuilt);
        rebuilt.extend_from_slice(&value);
        decode_ts_request(&rebuilt)?
    } else {
        let mut full = Vec::with_capacity(2 + total_len);
        full.push(header[0]);
        full.push(header[1]);
        full.extend_from_slice(&value);
        decode_ts_request(&full)?
    };

    tracing::debug!(
        "CredSSP: received TSRequest (version={}, nego_tokens_len={:?}, auth_info_len={:?}, pub_key_auth_len={:?}, error_code={:?})",
        decoded.version,
        decoded.nego_tokens.as_ref().map(|v| v.len()),
        decoded.auth_info.as_ref().map(|v| v.len()),
        decoded.pub_key_auth.as_ref().map(|v| v.len()),
        decoded.error_code
    );

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_request_roundtrip() {
        let req = TsRequest {
            version: 6,
            nego_tokens: Some(vec![1, 2, 3]),
            auth_info: Some(vec![4, 5, 6]),
            pub_key_auth: Some(vec![7, 8, 9]),
            error_code: Some(0x80090308),
            client_nonce: Some(vec![0xa; 32]),
        };
        let encoded = encode_ts_request(&req);
        let decoded = decode_ts_request(&encoded).unwrap();
        assert_eq!(decoded.version, req.version);
        assert_eq!(decoded.nego_tokens, req.nego_tokens);
        assert_eq!(decoded.auth_info, req.auth_info);
        assert_eq!(decoded.pub_key_auth, req.pub_key_auth);
        assert_eq!(decoded.error_code, req.error_code);
        assert_eq!(decoded.client_nonce, req.client_nonce);
    }
}