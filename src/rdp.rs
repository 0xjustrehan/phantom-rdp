/// RDP Connection Orchestrator
///
/// Drives the full connection sequence:
///   1. TCP connect
///   2. X.224 Connection Request (NLA negotiation)
///   3. X.224 Connection Confirm (verify NLA was accepted)
///   4. TLS upgrade over the existing TCP connection
///   5. Extract server TLS public key (for CredSSP channel binding)
///   6. Run CredSSP / NTLMv2 authentication
///   7. Return AuthResult
///
/// Everything stops right after auth — no MCS, no channel setup, no graphics.
use std::io;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream as RustlsTlsStream;
use tokio_rustls::TlsConnector;

use crate::cssp::{run_credssp, AuthResult};
use crate::error::{RdpError, Result};
use crate::tpkt::{read_tpkt, write_tpkt};
use crate::x224::{build_connection_request, parse_connection_confirm, PROTOCOL_HYBRID};
use tokio::net::TcpStream;

// ── Global cached TLS config (rustls fast path) ───────────────────────────────
// rustls (ring) is ~6x cheaper per handshake than OpenSSL — this cached config
// is the default path for every attempt. `--enable-tls-resumption` swaps in a
// one-off config with resumption enabled instead.
static TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| Arc::new(make_tls_config()));

// ── Global cached OpenSSL connector (legacy fallback) ────────────────────────
// Only used when the server rejects the rustls TLS 1.2+ handshake — i.e.
// legacy RDP targets (Server 2003/2008) that only speak TLS 1.0/1.1, which
// rustls (min TLS 1.2) can never reach. Statically linked (vendored) on all
// targets; on Windows it deliberately is NOT SChannel (too slow per handshake).

/// Global counter of currently in-flight TCP+TLS+CredSSP connections.
/// Used by the progress bar to show real-time connection saturation.
pub static ACTIVE_CONNECTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The authentication engine to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Engine {
    Custom,
    Raw,
}

/// Configuration for a single RDP credential check.
#[derive(Debug, Clone)]
pub struct RdpCheckConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: String,
    /// Overall timeout for the entire auth sequence (default: 10s).
    pub timeout_ms: u64,
    /// Authentication engine to use.
    pub engine: Engine,
    pub precomputed_nt_hash: Option<[u8; 16]>,
    pub handshake_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Stealth mode: skip SO_LINGER(0) RST and use normal FIN teardown.
    /// Reduces IDS/firewall fingerprinting at the cost of slower port recycling.
    pub stealth: bool,
    /// Optional SOCKS5 proxy URL, e.g. "socks5://127.0.0.1:1080" or "socks5://user:pass@host:port".
    pub proxy: Option<String>,
    /// Enable TLS session resumption (disabled by default — most RDP servers reject it).
    pub tls_resumption: bool,
}

impl RdpCheckConfig {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            domain: domain.into(),
            timeout_ms: 6000,
            engine: Engine::Custom,
            precomputed_nt_hash: None,
            handshake_semaphore: None,
            stealth: false,
            proxy: None,
            tls_resumption: false,
        }
    }
}

pub async fn check_credentials(cfg: &RdpCheckConfig) -> Result<AuthResult> {
    let mut _permit = None;
    if let Some(ref sem) = cfg.handshake_semaphore {
        // Try to acquire a handshake slot with a 500ms timeout.
        // If all slots are held by timing-out connections, skip this attempt
        // instead of blocking forever behind the queue.
        match tokio::time::timeout(Duration::from_millis(500), sem.clone().acquire_owned()).await {
            Ok(Ok(p)) => _permit = Some(p),
            Ok(Err(e)) => return Err(RdpError::ProtocolMsg(format!("Semaphore closed: {e}"))),
            Err(_) => {
                return Err(RdpError::ProtocolMsg(
                    "Handshake slots full (backpressure)".into(),
                ))
            }
        }
    }

    // Track active in-flight connections
    ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let attempt_result = timeout(
        Duration::from_millis(cfg.timeout_ms),
        do_check(cfg, _permit),
    )
    .await;

    ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

    match attempt_result {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(RdpError::Timeout),
    }
}


async fn do_check(
    cfg: &RdpCheckConfig,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<AuthResult> {
    let handshake_fut = async {
        // ── 1-3. TCP connect + X.224 NLA negotiation (direct or SOCKS5) ────────
        let tcp = connect_nla(cfg).await?;

        // ── 4. TLS upgrade ────────────────────────────────────────────────────
        // Fast path: rustls (ring) — ~6x cheaper per handshake than OpenSSL,
        // which is what keeps the spray rate at the rustls-era PPS level.
        // Legacy targets (Server 2003/2008 = TLS 1.0 only) reject TLS 1.2+:
        // detect that and retry the whole handshake through the OpenSSL
        // fallback (TLS 1.0 capable). TCP-level failures never reach this
        // point, so dead targets don't pay for a second attempt.
        let tls_stream = TlsTransport::Rustls(tls_upgrade_rustls(tcp, cfg).await?);
        tracing::debug!("TLS handshake complete");

        Ok::<_, RdpError>(tls_stream)
    };

    // Handshake should get most of the time (TCP + X.224 + TLS takes the longest)
    // We give it 80% of the total timeout, but at least 2 seconds.
    let hs_timeout = Duration::from_millis(cfg.timeout_ms)
        .mul_f64(0.8)
        .max(Duration::from_secs(2));
    let mut tls_stream = timeout(hs_timeout, handshake_fut)
        .await
        .map_err(|_| RdpError::Timeout)??;

    // Release the handshake concurrency permit immediately after TLS upgrade is done
    drop(permit);

    // ── 5. Extract server public key ──────────────────────────────────────────
    let server_pubkey = extract_server_pubkey(&tls_stream)?;
    tracing::debug!(
        "Server public key extracted ({} bytes)",
        server_pubkey.len()
    );

    // ── 6. CredSSP / NTLMv2 ──────────────────────────────────────────────────
    // "." is our CLI placeholder for "no domain" — normalize to empty so the
    // NTLM message and TSCredentials match mstsc/SSPI (server decides: local
    // SAM on members, real domain on DCs). A literal "." forces local-only
    // validation and breaks domain accounts / DCs.
    let domain = if cfg.domain == "." { "" } else { cfg.domain.as_str() };
    let result = match &cfg.engine {
        Engine::Custom => {
            run_credssp(
                &mut tls_stream,
                &cfg.username,
                &cfg.password,
                domain,
                &server_pubkey,
                cfg.precomputed_nt_hash,
            )
            .await
        }
        Engine::Raw => {
            crate::raw::run_raw_engine(
                &mut tls_stream,
                &cfg.username,
                &cfg.password,
                domain,
                &server_pubkey,
                cfg.precomputed_nt_hash,
            )
            .await
        }
    };

    match result {
        Ok(auth) => Ok(auth),
        Err(e) => Err(e),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS helpers
// ──────────────────────────────────────────────────────────────────────────────

/// TLS transport for the CredSSP phase — either the rustls fast path or the
/// OpenSSL legacy fallback. Both are full-duplex async streams over TCP, so
/// CredSSP runs identically on top of either.
enum TlsTransport {
    Rustls(RustlsTlsStream<TcpStream>),
}

impl AsyncRead for TlsTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsTransport::Rustls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TlsTransport::Rustls(s) => Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsTransport::Rustls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TlsTransport::Rustls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TlsTransport::Rustls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            TlsTransport::Rustls(s) => s.is_write_vectored(),
        }
    }
}

/// Steps 1-3 of the RDP sequence: TCP connect (direct or via SOCKS5), then the
/// X.224 Connection Request/Confirm handshake. Returns the connected stream
/// positioned right before the TLS upgrade.
async fn connect_nla(cfg: &RdpCheckConfig) -> Result<TcpStream> {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let tcp = if let Some(ref proxy_url) = cfg.proxy {
        // Parse socks5://[user:pass@]host:port
        let url = proxy_url.trim_start_matches("socks5://");
        let (auth, hostport) = if url.contains('@') {
            let mut parts = url.splitn(2, '@');
            let creds = parts.next().unwrap_or("");
            let hp = parts.next().unwrap_or("");
            (Some(creds), hp)
        } else {
            (None, url)
        };
        let proxy_stream = TcpStream::connect(hostport).await
            .map_err(|e| RdpError::ProtocolMsg(format!("SOCKS5 proxy connect failed: {e}")))?;
        if let Some(creds) = auth {
            let mut c = creds.splitn(2, ':');
            let user = c.next().unwrap_or("");
            let pass = c.next().unwrap_or("");
            tokio_socks::tcp::Socks5Stream::connect_with_password_and_socket(
                proxy_stream,
                addr.as_str(),
                user,
                pass,
            ).await
                .map_err(|e| RdpError::ProtocolMsg(format!("SOCKS5 auth failed: {e}")))?.
                into_inner()
        } else {
            tokio_socks::tcp::Socks5Stream::connect_with_socket(
                proxy_stream,
                addr.as_str(),
            ).await
                .map_err(|e| RdpError::ProtocolMsg(format!("SOCKS5 connect failed: {e}")))?.
                into_inner()
        }
    } else {
        // Fast connect timeout: don't stall the worker if the host is down/dropped by firewall
        let connect_timeout = Duration::from_millis(cfg.timeout_ms.min(2500).max(1000));
        match tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(RdpError::Io(e)),
            Err(_) => return Err(RdpError::Timeout),
        }
    };
    tcp.set_nodelay(true)?;
    // SO_LINGER(0): send RST on close instead of FIN.
    // This makes the port instantly recyclable (no 30s TIME_WAIT).
    // Skip in stealth mode — RSTs are a very strong IDS/IPS fingerprint.
    if !cfg.stealth {
        #[allow(deprecated)]
        let _ = tcp.set_linger(Some(Duration::ZERO));
    }
    tracing::debug!("TCP connected to {addr}");

    // X.224 Connection Request → Connection Confirm (NLA must be selected)
    let (mut reader, mut writer) = tokio::io::split(tcp);
    let cr_pdu = build_connection_request(Some("anonymous"));
    write_tpkt(&mut writer, &cr_pdu).await?;
    tracing::debug!("X.224 Connection Request sent");

    let cc_payload = read_tpkt(&mut reader).await?;
    let cc = parse_connection_confirm(&cc_payload)?;

    if (cc.selected_protocol & PROTOCOL_HYBRID) == 0 {
        return Err(RdpError::ProtocolMsg(format!(
            "Server did not select NLA (PROTOCOL_HYBRID). Selected: 0x{:08X}. \
             Ensure 'Network Level Authentication' is enabled on the target.",
            cc.selected_protocol
        )));
    }
    tracing::debug!("X.224 Confirm received — protocol: PROTOCOL_HYBRID");

    Ok(reader.unsplit(writer))
}

/// Fast-path TLS upgrade via rustls (ring).
///
/// Fails for legacy targets that only speak TLS 1.0/1.1 — the caller then
/// retries the whole handshake through `tls_upgrade_openssl`.
async fn tls_upgrade_rustls(
    tcp: TcpStream,
    cfg: &RdpCheckConfig,
) -> Result<RustlsTlsStream<TcpStream>> {
    let server_name = ServerName::try_from(cfg.host.clone())
        .map_err(|e| RdpError::ProtocolMsg(format!("Invalid server name: {e}")))?;

    // Use cached global TLS config (avoids rebuilding crypto state per
    // connection). When --enable-tls-resumption is set, build a separate
    // config with resumption enabled.
    let tls_cfg = if cfg.tls_resumption {
        Arc::new(make_tls_config_with_resumption())
    } else {
        TLS_CONFIG.clone()
    };

    let connector = TlsConnector::from(tls_cfg);
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| RdpError::ProtocolMsg(format!("rustls handshake: {e}")))
}

/// A custom ServerCertVerifier that accepts any certificate.
///
/// This is intentional: RDP servers use self-signed certificates and we are
/// only verifying credentials, not server identity.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Build a TLS ClientConfig that accepts any server certificate.
/// Session resumption is explicitly DISABLED — RDP servers reject resumed TLS
/// sessions with `AlertReceived(InternalError)`, breaking the auth engines.
fn make_tls_config() -> ClientConfig {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    // Disable TLS session ticket caching. Without this, rustls reuses the
    // session from a previous connection and the server responds with
    // InternalError.
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg
}

/// TLS config with session resumption ENABLED. Only use with
/// --enable-tls-resumption. Some older Windows targets (Server 2008, XP) may
/// benefit from this.
fn make_tls_config_with_resumption() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

/// Extract the DER-encoded SubjectPublicKeyInfo from the server's leaf certificate.
fn extract_server_pubkey(stream: &TlsTransport) -> Result<Vec<u8>> {
    let der = match stream {
        TlsTransport::Rustls(s) => {
            let (_, session) = s.get_ref();
            let certs = session
                .peer_certificates()
                .ok_or(RdpError::Protocol("TLS: server sent no certificates"))?;
            let leaf = certs
                .first()
                .ok_or(RdpError::Protocol("TLS: certificate chain is empty"))?;
            leaf.as_ref().to_vec()
        }
    };

    // Parse the DER cert to extract the SubjectPublicKeyInfo
    extract_spki_from_der(&der)
}

/// Minimal DER X.509 parser to extract SubjectPublicKeyInfo bytes.
///
/// X.509 TBSCertificate structure (simplified):
///   Certificate ::= SEQUENCE {
///     tbsCertificate  TBSCertificate,
///     ...
///   }
///   TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT Version OPTIONAL,
///     serialNumber    CertificateSerialNumber,
///     signature       AlgorithmIdentifier,
///     issuer          Name,
///     validity        Validity,
///     subject         Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,  ← we want this
///     ...
///   }
fn extract_spki_from_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Windows CredSSP verifies the pubKeyAuth hash against the RSAPublicKey
    // bytes (the BIT STRING content), NOT the full SubjectPublicKeyInfo —
    // verified empirically against Server 2016-2022 (a full-SPKI hash gets
    // the connection rejected). picky parses the cert and re-encodes the
    // PublicKey, which is byte-identical to the original BIT STRING content
    // for every cert shape we have met.
    let cert: picky_asn1_x509::Certificate = picky_asn1_der::from_bytes(cert_der).map_err(|e| {
        tracing::error!("picky_asn1_der error: {:?}", e);
        RdpError::Protocol("TLS: failed to parse X.509 certificate with picky")
    })?;

    let raw_public_key = match cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
    {
        picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0).unwrap(),
        picky_asn1_x509::PublicKey::Ec(ec) => picky_asn1_der::to_vec(&ec).unwrap(),
        picky_asn1_x509::PublicKey::Ed(ed) => picky_asn1_der::to_vec(&ed).unwrap(),
        picky_asn1_x509::PublicKey::Mldsa(mldsa) => picky_asn1_der::to_vec(&mldsa).unwrap(),
    };

    Ok(raw_public_key)
}

pub fn is_connection_reset(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

#[derive(Debug, Clone, Default)]
pub struct DomainInfo {
    pub nb_domain: String,
    pub dns_domain: String,
    pub computer_name: String,
    pub dns_tree: String,
    /// Windows OS version string parsed from the NTLM Type-2 challenge Version field.
    /// e.g. "Windows 10 (19041)", "Server 2019 (17763)", "Windows 7 (7601)"
    pub os_version: Option<String>,
}

impl std::fmt::Display for DomainInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let domain = if !self.nb_domain.is_empty() {
            &self.nb_domain
        } else if !self.dns_domain.is_empty() {
            &self.dns_domain
        } else {
            ""
        };

        if !domain.is_empty() {
            write!(f, "{}", domain)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub enum NlaProbeResult {
    NlaEnabled,
    NoNla(String),
    Timeout,
    Error(String),
}

pub async fn probe_nla(host: &str, port: u16, timeout_ms: u64) -> NlaProbeResult {
    let timeout_dur = Duration::from_millis(timeout_ms);
    let attempt = timeout(timeout_dur, async {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await?;
        tcp.set_nodelay(true)?;

        let (mut reader, mut writer) = tokio::io::split(tcp);
        let cr_pdu = build_connection_request(Some("anonymous"));
        write_tpkt(&mut writer, &cr_pdu).await?;

        let cc_payload = read_tpkt(&mut reader).await?;
        let cc = parse_connection_confirm(&cc_payload)?;

        if (cc.selected_protocol & PROTOCOL_HYBRID) != 0 {
            Ok::<_, RdpError>(NlaProbeResult::NlaEnabled)
        } else {
            Ok(NlaProbeResult::NoNla(format!(
                "Server did not select NLA. Selected: 0x{:08X}",
                cc.selected_protocol
            )))
        }
    })
    .await;

    match attempt {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => NlaProbeResult::Error(e.to_string()),
        Err(_) => NlaProbeResult::Timeout,
    }
}

pub fn parse_target(target: &str) -> (String, u16) {
    if target.starts_with('[') {
        if let Some(end) = target.find(']') {
            let host = &target[1..end];
            let port_str = target.get(end + 1..);
            if let Some(p_str) = port_str {
                if p_str.starts_with(':') {
                    let p = p_str[1..].parse().unwrap_or(3389);
                    return (host.to_string(), p);
                }
            }
            return (host.to_string(), 3389);
        }
    } else if let Some(last_colon) = target.rfind(':') {
        // If there are multiple colons, and it doesn't start with [, it's likely a raw IPv6 address without a port
        if target.find(':') != Some(last_colon) {
            return (target.to_string(), 3389);
        }
        let (h, p) = target.split_at(last_colon);
        let p_val = p[1..].parse().unwrap_or(3389);
        return (h.to_string(), p_val);
    }

    (target.to_string(), 3389)
}
