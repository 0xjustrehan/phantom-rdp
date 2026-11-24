use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

/// Thread-safe attempt tracker per target host to prevent Active Directory account lockouts
pub struct AttemptTracker {
    attempts: Mutex<HashMap<String, usize>>,
    max_tries: usize,
}

impl AttemptTracker {
    pub fn new(max_tries: usize) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_tries,
        }
    }

    /// Check if target host can be probed and increment attempt count
    pub fn can_attempt(&self, host: &str) -> bool {
        if self.max_tries == 0 {
            return true; // Unlimited
        }

        let mut lock = self.attempts.lock().unwrap();
        let count = lock.entry(host.to_string()).or_insert(0);
        if *count >= self.max_tries {
            return false;
        }

        *count += 1;
        true
    }

    /// Mark target as successfully cracked or locked to halt further attempts
    pub fn retire_host(&self, host: &str) {
        let mut lock = self.attempts.lock().unwrap();
        lock.insert(host.to_string(), usize::MAX / 2);
    }
}

/// Extract /24 prefix for IPv4 or /48 for IPv6
pub fn extract_subnet_key(target: &str) -> String {
    let host = if let Some(idx) = target.rfind(':') {
        &target[..idx]
    } else {
        target
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    } else {
        host.to_string()
    }
}

/// Interleaves targets across distinct /24 subnets so adjacent attempts never hit the same subnet
pub fn interleave_targets(targets: &[String]) -> Vec<String> {
    if targets.len() <= 2 {
        return targets.to_vec();
    }

    let mut buckets: HashMap<String, Vec<String>> = HashMap::new();
    let mut subnet_order: Vec<String> = Vec::new();

    for t in targets {
        let subnet = extract_subnet_key(t);
        if !buckets.contains_key(&subnet) {
            subnet_order.push(subnet.clone());
        }
        buckets.entry(subnet).or_default().push(t.clone());
    }

    // Shuffle subnet keys
    fastrand::shuffle(&mut subnet_order);

    let mut result = Vec::with_capacity(targets.len());
    loop {
        let mut added = false;
        for subnet in &subnet_order {
            if let Some(list) = buckets.get_mut(subnet) {
                if !list.is_empty() {
                    result.push(list.remove(0));
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }

    result
}

/// Apply micro-jitter in milliseconds
pub async fn apply_jitter(max_ms: u64) {
    if max_ms > 0 {
        let ms = fastrand::u64(0..=max_ms);
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
}
