/// Raw Engine — Full CredSSP / NTLMv2 handshake implemented in pure Rust
///
/// This is a completely self-contained CredSSP implementation that mirrors what
/// `run_credssp` in cssp.rs does, but with its own independent code path so it
/// runs as a separate engine with its own worker pool.
///
/// It performs all 5 MS-CSSP steps:
///   1. TSRequest { negoTokens: [NTLM Negotiate] }  → server
///   2. TSRequest { negoTokens: [NTLM Challenge] }  ← server
///   3. TSRequest { negoTokens: [NTLM Authenticate], pubKeyAuth }  → server
///   4. TSRequest { pubKeyAuth }  ← server (optional server confirm)
///   5. TSRequest { authInfo: TSCredentials (RC4-encrypted) }  → server
///
/// The pubKeyAuth token uses NTLM signing with the exported session key and a
/// SHA-256 hash of the TLS server public key + client nonce + magic string
/// (CredSSP v5+ binding hash per MS-CSSP §3.1.5.2.1).
use crate::asn1::{
    encode_len, wrap_ctx, wrap_sequence, write_integer_u32, write_octet_string, TAG_SEQUENCE,
};
use crate::cssp::{decode_ts_request, encode_ts_request, AuthResult, TsRequest};
use crate::error::{RdpError, Result};
use crate::ntlm::{build_authenticate, build_negotiate, parse_challenge, unicode};
use crate::spnego::extract_ntlm_from_spnego;

use hmac::{Hmac, Mac};
use md5::Md5;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type HmacMd5 = Hmac<Md5>;

const CREDSSP_VERSION: u32 = 6;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hmac_md5_raw(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn random_bytes_32() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 32];
    SystemRandom::new().fill(&mut buf).expect("random bytes");
    buf
}

// ─────────────────────────────────────────────────────────────────────────────
// Inline RC4 (same as cssp.rs — avoids generic_array ambiguity from rc4 crate)
// ─────────────────────────────────────────────────────────────────────────────

struct Rc4 {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4 {
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

fn rc4_seal(key: &[u8], data: &[u8]) -> Vec<u8> {
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
    let (mut i, mut jj) = (0usize, 0usize);
    for byte in out.iter_mut() {
        i = (i + 1) % 256;
        jj = (jj + s[i] as usize) % 256;
        s.swap(i, jj);
        *byte ^= s[(s[i] as usize + s[jj] as usize) % 256];
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// pubKeyAuth builder
// Builds NTLMSSP_MESSAGE wrapped pubKeyAuth token for CredSSP v5+
// ─────────────────────────────────────────────────────────────────────────────

fn build_pub_key_auth(
    exported_session_key: &[u8],
    server_pubkey: &[u8],
    client_nonce: &[u8],
    credssp_version: u32,
) -> Vec<u8> {
    use md5::{Digest, Md5};
    use sha2::{Digest as Sha256Digest, Sha256};

    // 1. Derive client signing and sealing keys (per MS-NLMP §3.4.5.2)
    let client_signing_key: [u8; 16] = {
        let mut h = Md5::new();
        h.update(exported_session_key);
        h.update(b"session key to client-to-server signing key magic constant\0");
        h.finalize().into()
    };
    let client_sealing_key: [u8; 16] = {
        let mut h = Md5::new();
        h.update(exported_session_key);
        h.update(b"session key to client-to-server sealing key magic constant\0");
        h.finalize().into()
    };

    // 2. CredSSP version-dependent binding (MS-CSSP §3.1.5.2.1 / sspi-rs):
    //    peer v5+: SHA256("CredSSP Client-To-Server Binding Hash\0" || clientNonce || SPKI)
    //    peer v2-v4: echo the SPKI bytes themselves (no hash at all)
    let payload: Vec<u8> = if credssp_version >= 5 {
        let mut h = Sha256::new();
        h.update(b"CredSSP Client-To-Server Binding Hash\0");
        h.update(client_nonce);
        h.update(server_pubkey);
        h.finalize().to_vec()
    } else {
        server_pubkey.to_vec()
    };

    // 3. Encrypt payload with RC4(ClientSealingKey)
    let mut rc4 = Rc4::new(&client_sealing_key);
    let mut encrypted_msg = payload.to_vec();
    rc4.crypt(&mut encrypted_msg);

    // 4. Compute HMAC-MD5 checksum over (SeqNum=0 || plaintext)
    let seq_num = 0u32;
    let mut mac_input = Vec::with_capacity(4 + payload.len());
    mac_input.extend_from_slice(&seq_num.to_le_bytes());
    mac_input.extend_from_slice(&payload);
    let checksum_full = hmac_md5_raw(&client_signing_key, &mac_input);

    // 5. Encrypt checksum with SAME continuous RC4 state
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&checksum_full[0..8]);
    rc4.crypt(&mut checksum);

    // 6. Build NTLMSSP_MESSAGE_SIGNATURE (16 bytes) + encrypted payload
    let mut sig = [0u8; 16];
    sig[0..4].copy_from_slice(&1u32.to_le_bytes()); // Version = 1
    sig[4..12].copy_from_slice(&checksum);
    sig[12..16].copy_from_slice(&seq_num.to_le_bytes());

    let mut out = Vec::with_capacity(16 + encrypted_msg.len());
    out.extend_from_slice(&sig);
    out.extend_from_slice(&encrypted_msg);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// TSRequest send/receive (mirrors cssp.rs internals)
// ─────────────────────────────────────────────────────────────────────────────

async fn send_ts<S: AsyncWrite + Unpin>(stream: &mut S, req: &TsRequest) -> Result<()> {
    let encoded = encode_ts_request(req);
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

async fn recv_ts<S: AsyncRead + Unpin>(stream: &mut S) -> Result<TsRequest> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != TAG_SEQUENCE {
        return Err(RdpError::ProtocolMsg(format!(
            "Raw CredSSP: expected SEQUENCE (0x30), got 0x{:02X}",
            header[0]
        )));
    }

    let (total_len, extra_header) = if header[1] < 0x80 {
        (header[1] as usize, 0)
    } else {
        let extra = (header[1] & 0x7F) as usize;
        if extra > 4 {
            return Err(RdpError::Protocol(
                "Raw CredSSP: oversized TSRequest length",
            ));
        }
        let mut lb = vec![0u8; extra];
        stream.read_exact(&mut lb).await?;
        let mut len = 0usize;
        for b in &lb {
            len = (len << 8) | (*b as usize);
        }
        (len, extra)
    };

    let mut value = vec![0u8; total_len];
    stream.read_exact(&mut value).await?;

    let decoded = if extra_header > 0 {
        let mut rebuilt = Vec::new();
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

    Ok(decoded)
}

// ─────────────────────────────────────────────────────────────────────────────
// TSCredentials encoder (mirrors cssp.rs encode_ts_credentials)
// ─────────────────────────────────────────────────────────────────────────────

fn encode_ts_creds(domain: &str, username: &str, password: &str) -> Vec<u8> {
    // TSPasswordCreds
    let mut pw_inner = Vec::new();
    let dom16 = unicode(domain);
    let mut dom_oct = Vec::new();
    write_octet_string(&dom16, &mut dom_oct);
    wrap_ctx(0, &dom_oct, &mut pw_inner);
    let user16 = unicode(username);
    let mut user_oct = Vec::new();
    write_octet_string(&user16, &mut user_oct);
    wrap_ctx(1, &user_oct, &mut pw_inner);
    let pass16 = unicode(password);
    let mut pass_oct = Vec::new();
    write_octet_string(&pass16, &mut pass_oct);
    wrap_ctx(2, &pass_oct, &mut pw_inner);
    let mut pw_seq = Vec::new();
    wrap_sequence(&pw_inner, &mut pw_seq);

    // TSCredentials
    let mut ts_inner = Vec::new();
    let mut cred_type_bytes = Vec::new();
    write_integer_u32(1, &mut cred_type_bytes);
    wrap_ctx(0, &cred_type_bytes, &mut ts_inner);
    let mut creds_oct = Vec::new();
    write_octet_string(&pw_seq, &mut creds_oct);
    wrap_ctx(1, &creds_oct, &mut ts_inner);
    let mut ts_creds = Vec::new();
    wrap_sequence(&ts_inner, &mut ts_creds);
    ts_creds
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full 5-step CredSSP handshake over an already-established TLS stream.
///
/// `server_pubkey` is the raw DER-encoded SubjectPublicKeyInfo (SPKI) of the
/// server's TLS certificate, used for channel binding in the pubKeyAuth token.
pub async fn run_raw_engine<S>(
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
    // 32-byte client nonce (CredSSP v5+)
    let client_nonce = random_bytes_32();

    // ── Step 1: Send NTLM Negotiate ──────────────────────────────────────────
    let negotiate_raw = build_negotiate();
    let req1 = TsRequest {
        version: CREDSSP_VERSION,
        nego_tokens: Some(negotiate_raw.clone()),
        client_nonce: Some(client_nonce.to_vec()),
        ..Default::default()
    };
    send_ts(stream, &req1).await?;
    tracing::debug!("Raw CredSSP: sent TSRequest 1 (NTLM Negotiate)");

    // ── Step 2: Receive NTLM Challenge ───────────────────────────────────────
    let resp1 = recv_ts(stream).await?;

    // CredSSP: keep our max version (6) in every TSRequest (sspi-rs/mstsc
    // behavior); only the pubKeyAuth *format* adapts to the peer version.
    let credssp_ver = if (2..=6).contains(&resp1.version) {
        resp1.version
    } else {
        CREDSSP_VERSION
    };
    tracing::debug!("Raw CredSSP: peer protocol version {credssp_ver} (we keep sending v{CREDSSP_VERSION})");

    if let Some(code) = resp1.error_code {
        return Ok(AuthResult {
            success: false,
            reason: Some(format!("Raw CredSSP: server error in step 2: 0x{code:08X}")),
            domain_info: None,
            ntstatus: Some(code as u32),
        });
    }

    let nego_token = resp1
        .nego_tokens
        .ok_or_else(|| RdpError::Protocol("Raw CredSSP: server TSRequest 2 missing negoTokens"))?;

    // Handle both SPNEGO-wrapped and raw NTLM Challenge
    let challenge_raw = if nego_token.starts_with(b"NTLMSSP\0") {
        nego_token.clone()
    } else {
        extract_ntlm_from_spnego(&nego_token)?
    };

    let challenge = parse_challenge(&challenge_raw)?;
    tracing::debug!("Raw CredSSP: received NTLM Challenge");

    // ── Step 3: Build NTLM Authenticate + pubKeyAuth ─────────────────────────
    let auth_result = build_authenticate(
        &challenge,
        username,
        password,
        domain,
        "", // workstation
        &negotiate_raw,
        &challenge_raw,
        precomputed_nt_hash,
    )?;

    let pub_key_auth = build_pub_key_auth(
        &auth_result.exported_session_key,
        server_pubkey,
        &client_nonce,
        credssp_ver,
    );
    tracing::debug!(
        "Raw CredSSP: pubKeyAuth built ({} bytes, session_key={:02x?})",
        pub_key_auth.len(),
        &auth_result.exported_session_key[..4]
    );

    let req2 = TsRequest {
        version: CREDSSP_VERSION,
        nego_tokens: Some(auth_result.authenticate_message.clone()),
        pub_key_auth: Some(pub_key_auth),
        client_nonce: Some(client_nonce.to_vec()),
        ..Default::default()
    };
    send_ts(stream, &req2).await?;
    tracing::debug!("Raw CredSSP: sent TSRequest 3 (NTLM Authenticate + pubKeyAuth)");

    // ── Step 4: Server pubKeyAuth confirmation ────────────────────────────────
    let resp2 = match recv_ts(stream).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("Raw CredSSP: connection reset after NTLM auth (invalid credentials): {:?}", e);
            return Ok(crate::cssp::parse_ntstatus(
                0xC000006D,
                Some(challenge.domain_info),
            ));
        }
    };

    if let Some(code) = resp2.error_code {
        return Ok(crate::cssp::parse_ntstatus(
            code as u32,
            Some(challenge.domain_info),
        ));
    }

    tracing::debug!("Raw CredSSP: received server pubKeyAuth confirmation");

    // ── Step 5: Send TSCredentials (RC4-encrypted with exported session key) ──
    let ts_creds = encode_ts_creds(domain, username, password);
    let encrypted = rc4_seal(&auth_result.exported_session_key, &ts_creds);

    let req3 = TsRequest {
        version: CREDSSP_VERSION,
        auth_info: Some(encrypted),
        ..Default::default()
    };
    send_ts(stream, &req3).await?;
    tracing::debug!("Raw CredSSP: sent TSRequest 5 (TSCredentials) — handshake complete");

    // ── Wait for final server response or clean close ─────────────────────────
    let final_res = recv_ts(stream).await;
    match final_res {
        Ok(resp3) => {
            if let Some(code) = resp3.error_code {
                return Ok(crate::cssp::parse_ntstatus(
                    code as u32,
                    Some(challenge.domain_info),
                ));
            }
            Ok(AuthResult {
                success: true,
                reason: None,
                domain_info: Some(challenge.domain_info),
                ntstatus: Some(0xC0000000),
            })
        }
        Err(e) => {
            tracing::debug!("Raw CredSSP: connection closed or error reading final response (expected on success): {:?}", e);
            Ok(AuthResult {
                success: true,
                reason: None,
                domain_info: Some(challenge.domain_info),
                ntstatus: Some(0xC0000000),
            })
        }
    }
}
