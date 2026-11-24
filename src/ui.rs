use std::io::{stdout, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct EngineStats {
    pub total_tasks: AtomicU64,
    pub completed_tasks: AtomicU64,
    pub goods: AtomicU64,
    pub honeypots: AtomicU64,
    pub errors: AtomicU64,
    pub lockouts: AtomicU64,
    pub f2b_guarded: AtomicU64,
}

pub struct LiveUi {
    stats: Arc<EngineStats>,
    start_time: Instant,
    recent_hits: Mutex<Vec<String>>,
    no_tui: bool,
    quiet: bool,
}

impl LiveUi {
    pub fn new(stats: Arc<EngineStats>, no_tui: bool, quiet: bool) -> Self {
        Self {
            stats,
            start_time: Instant::now(),
            recent_hits: Mutex::new(Vec::new()),
            no_tui,
            quiet,
        }
    }

    pub fn add_hit(&self, text: String) {
        if self.no_tui {
            if !self.quiet {
                println!("{text}");
            }
            return;
        }

        let mut lock = self.recent_hits.lock().unwrap();
        lock.push(text);
        if lock.len() > 8 {
            lock.remove(0);
        }
    }

    pub fn render(&self) {
        if self.no_tui || self.quiet {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let completed = self.stats.completed_tasks.load(Ordering::Relaxed);
        let total = self.stats.total_tasks.load(Ordering::Relaxed);
        let goods = self.stats.goods.load(Ordering::Relaxed);
        let honeypots = self.stats.honeypots.load(Ordering::Relaxed);
        let errors = self.stats.errors.load(Ordering::Relaxed);
        let lockouts = self.stats.lockouts.load(Ordering::Relaxed);
        let guarded = self.stats.f2b_guarded.load(Ordering::Relaxed);

        let rate = if elapsed > 0.0 {
            completed as f64 / elapsed
        } else {
            0.0
        };

        let pct = if total > 0 {
            (completed as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        let eta_str = if rate > 0.0 && total > completed {
            let rem_secs = (total - completed) as f64 / rate;
            format_duration(Duration::from_secs(rem_secs as u64))
        } else {
            "00:00:00".to_string()
        };

        let box_width = 76;
        let mut out = String::new();

        // Terminal clear & cursor home
        out.push_str("\x1b[H\x1b[2J");

        out.push_str("╔════════════════════════════════════════════════════════════════════════════╗\n");
        out.push_str("║        ⚡ PHANTOM-RDP v1.0.0 — Elite Stealth RDP Sprayer & Triager ⚡      ║\n");
        out.push_str("╠════════════════════════════════════════════════════════════════════════════╣\n");

        let status_line = format!(
            " Elapsed: {} | ETA: {} | Speed: {:.1} checks/s",
            format_duration(self.start_time.elapsed()),
            eta_str,
            rate
        );
        out.push_str(&pad_line(&status_line, box_width));
        out.push('\n');

        let bar_width = 40;
        let filled = ((pct / 100.0) * bar_width as f64).round() as usize;
        let filled = filled.min(bar_width);
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
        let prog_line = format!(" [{bar}] {pct:>5.1}% ({completed} / {total})");
        out.push_str(&pad_line(&prog_line, box_width));
        out.push('\n');

        out.push_str("╠════════════════════════════════════════════════════════════════════════════╣\n");

        let metrics_line = format!(
            " ✅ Goods: {goods} | 🍯 Honeypots: {honeypots} | ❌ Fails: {errors} | 🔒 Lockouts: {lockouts} | 🛡️ Guarded: {guarded}"
        );
        out.push_str(&pad_line(&metrics_line, box_width));
        out.push('\n');

        out.push_str("╠════════════════════════════════════════════════════════════════════════════╣\n");
        out.push_str(&pad_line(" 📡 Live Real-Time Hits & Telemetry:", box_width));
        out.push('\n');

        let hits = self.recent_hits.lock().unwrap();
        if hits.is_empty() {
            out.push_str(&pad_line("   (Listening for authenticated RDP sessions...)", box_width));
            out.push('\n');
        } else {
            for h in hits.iter() {
                out.push_str("║ ");
                out.push_str(&truncate_line(h, box_width - 2));
                out.push('\n');
            }
        }

        out.push_str("╚════════════════════════════════════════════════════════════════════════════╝\n");
        out.push_str("\x1b[90m [Ctrl+C] Gracefully Stop | Results saved in output directory\x1b[0m\n");

        print!("{out}");
        let _ = stdout().flush();
    }
}

fn pad_line(s: &str, width: usize) -> String {
    let plain_len = strip_ansi(s).chars().count();
    let pad = if width > plain_len + 2 {
        width - plain_len - 2
    } else {
        0
    };
    format!("║ {s}{space} ║", space = " ".repeat(pad))
}

fn truncate_line(s: &str, width: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= width {
        format!("{}{}", s, " ".repeat(width - chars.len())) + "║"
    } else {
        chars[..width - 3].iter().collect::<String>() + "... ║"
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut in_esc = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_esc = true;
            continue;
        }
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
