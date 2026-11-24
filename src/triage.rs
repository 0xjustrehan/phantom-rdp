use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local};
use crate::rdp::DomainInfo;

pub struct ResultWriter {
    output_dir: PathBuf,
    lock: Mutex<()>,
}

impl ResultWriter {
    pub fn new(output_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = output_dir.as_ref().to_path_buf();
        create_dir_all(&path)?;
        Ok(Self {
            output_dir: path,
            lock: Mutex::new(()),
        })
    }

    fn append_line(&self, filename: &str, line: &str) {
        let _guard = self.lock.lock().unwrap();
        let target_file = self.output_dir.join(filename);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(target_file) {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn record_good(
        &self,
        target: &str,
        domain: &str,
        user: &str,
        pass: &str,
        domain_info: Option<&DomainInfo>,
        rtt: Duration,
    ) {
        let resolved_domain = if !domain.is_empty() && domain != "." {
            domain
        } else if let Some(d) = domain_info {
            if !d.nb_domain.is_empty() {
                &d.nb_domain
            } else if !d.dns_domain.is_empty() {
                &d.dns_domain
            } else {
                "WORKGROUP"
            }
        } else {
            "WORKGROUP"
        };

        let cred_entry = format!("{target}@{resolved_domain}\\{user}:{pass}");

        // 1. Standard goods file
        self.append_line("good.txt", &cred_entry);

        // 2. Administrator classification
        let lower_user = user.to_lowercase();
        if lower_user == "administrator" || lower_user == "admin" || lower_user.contains("admin") {
            self.append_line("admin.txt", &cred_entry);
        }

        // 3. Detailed diagnostics
        let os_str = domain_info
            .and_then(|d| d.os_version.as_deref())
            .unwrap_or("Windows (Unknown)");
        let computer_str = domain_info
            .map(|d| d.computer_name.as_str())
            .unwrap_or("Unknown");
        let dns_tree_str = domain_info
            .map(|d| d.dns_tree.as_str())
            .unwrap_or("Unknown");

        let now: DateTime<Local> = SystemTime::now().into();
        let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

        let detail_card = format!(
            "╔══════════════════════════════════════════════════════════════\n\
             ║ 🎯 PHANTOM-RDP HIT: {target}\n\
             ╠══════════════════════════════════════════════════════════════\n\
             ║ 🔑 Credentials : {resolved_domain}\\{user}:{pass}\n\
             ║ 🖥️ Computer Name: {computer_str}\n\
             ║ 🏢 NetBIOS Dom : {resolved_domain}\n\
             ║ 🌲 DNS Tree Dom: {dns_tree_str}\n\
             ║ 🪟 OS Version  : {os_str}\n\
             ║ ⏱️ Response RTT: {rtt_ms}ms\n\
             ║ 🕒 Timestamp   : {timestamp}\n\
             ╚══════════════════════════════════════════════════════════════",
            rtt_ms = rtt.as_millis()
        );

        self.append_line("detailed.txt", &detail_card);
    }

    pub fn record_honeypot(&self, target: &str, user: &str, pass: &str) {
        let line = format!("{target} [User: {user} | Pass: {pass}] — Catch-All RDP Honeypot Disqualified");
        self.append_line("honeypots.txt", &line);
    }
}
