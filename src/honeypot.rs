use crate::rdp::{check_credentials, parse_target, Engine, RdpCheckConfig};

/// Probe if server is a catch-all fake RDP honeypot by testing a random canary credential
pub async fn check_canary_trap(
    target: &str,
    timeout_ms: u64,
    proxy: Option<String>,
) -> bool {
    let (host, port) = parse_target(target);
    let rand_suffix = fastrand::u32(..);
    let canary_user = format!("chk_canary_{rand_suffix:08x}");
    let canary_pass = format!("Bogus_Trap_{rand_suffix:08x}!@#9");

    let mut cfg = RdpCheckConfig::new(host, port, canary_user, canary_pass, ".");
    cfg.timeout_ms = timeout_ms;
    cfg.engine = Engine::Custom;
    cfg.proxy = proxy;

    match check_credentials(&cfg).await {
        Ok(auth) if auth.success => true, // Honeypot accepted random bogus password!
        _ => false,
    }
}
