# eBPF Cloud Runtime Guard: In-Kernel Enforcement & Covert DNS Defense

[![eBPF](https://img.shields.io/badge/eBPF-Linux%20Kernel%206.x-orange.svg)](https://ebpf.io/)
[![Cilium Tetragon](https://img.shields.io/badge/Enforcement-Cilium%20Tetragon%20v1.1.0-blue.svg)](https://tetragon.io/)
[![Docker Compose](https://img.shields.io/badge/Orchestration-Docker%20Compose%20v2-2496ED.svg)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Language-Python%203.11-3776AB.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/Compliance-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)

An enterprise-grade, dual-plane runtime security and forensic attribution framework for containerized cloud workloads. 

By instrumenting the Linux kernel with **Extended Berkeley Packet Filter (eBPF)** via **Cilium Tetragon**, the framework intercepts prohibited process execution synchronously at the `sys_execve` system call—delivering instantaneous, in-kernel `SIGKILL` terminations with **zero Time-of-Check to Time-of-Use (TOCTOU) latency**. At the egress network plane, an asynchronous DNS behavioral inspection proxy computes **Shannon Information Entropy** and RFC-1035 label heuristics on outbound UDP port 53 datagrams, actively sinkholing covert C2 tunneling payloads (Base64/Hex) while correlating egress requests with kernel-level Process IDs, User IDs, and parent binaries.

---

## Architecture Overview

```
+------------------------------------------------------------------------------------+
|                                    USER SPACE                                      |
|                                                                                    |
|   +------------------------------------+       +-------------------------------+   |
|   | Container: cloud-workload-app      |       | Container: dns-entropy-monitor|   |
|   | (UID: 13370 / GID: 13370)          |       | (Python 3.11 UDP Proxy)       |   |
|   |                                    |       |                               |   |
|   |  - GET  /api/v1/health             |       |  - Port 53 UDP Forwarder      |   |
|   |  - GET  /api/v1/tenants            |       |  - Shannon Entropy H(X) Engine|   |
|   |  - POST /api/v1/diagnostics (RCE)  |       |  - Sinkholing (NXDOMAIN)      |   |
|   +-----------------+------------------+       +---------------+---------------+   |
|                     | DNS Query (UDP 53)                       |                   |
|                     +------------------------------------------+                   |
|                                                                                    |
|   +----------------------------------------------------------------------------+   |
|   | Shared Volume: /var/log/tetragon/tetragon.log <-> dns_alerts.json          |   |
|   +----------------------------------------------------------------------------+   |
|                                          ^                                         |
|   +--------------------------------------+-------------------------------------+   |
|   | Container: tetragon (Privileged, Host PID, BPF Loader)                     |   |
|   +----------------------------------------------------------------------------+   |
+------------------------------------------|-----------------------------------------+
                                           | eBPF Programs & Perf Buffer
===========================================|==========================================
                                     KERNEL SPACE                                    
+------------------------------------------v-----------------------------------------+
|   Linux Kernel (BTF Enabled: /sys/kernel/btf/vmlinux)                              |
|                                                                                    |
|   [kprobe: sys_execve]                                                             |
|     * Inspects target binary path (arg0)                                           |
|     * Matches blocked binaries (/bin/dash, nc, wget)                               |
|     * Action: Synchronous in-kernel Sigkill                                        |
|                                                                                    |
|   [kprobe: udp_sendmsg / tcp_connect]                                              |
|     * Traces destination port 53 traffic                                           |
|     * Emits PID, UID, and binary telemetry to Ring Buffer                          |
+------------------------------------------------------------------------------------+
```

---

## Key Capabilities

1. **Synchronous In-Kernel Enforcement:**
   * Traditional user-space EDRs (auditd, osquery, shared-library hooks) exhibit a $10\text{--}50\text{ ms}$ processing lag, creating a window for attackers to dump memory or delete forensics.
   * Tetragon attaches kprobes directly to `sys_execve` in kernel space. When an unauthorized binary is spawned, the kernel delivers `SIGKILL` **before user-space instructions begin executing**.
2. **Behavioral DNS Entropy Defense:**
   * Enterprise firewalls typically permit unmonitored egress over UDP port 53. Malware exploits this to tunnel exfiltrated credentials within subdomains.
   * The proxy parses wire-format DNS datagrams and evaluates Shannon Entropy alongside label length and velocity limits, returning synthesized `NXDOMAIN` (RCODE 3) responses to neutralize tunnels.
3. **Cross-Plane Forensic Attribution:**
   * Solves the "blind firewall" problem by merging kernel socket telemetry with network query logs, binding every flagged query to the exact container PID, UID, and binary.
4. **Least-Privilege Isolation:**
   * The target microservice runs under a dedicated unprivileged user (`appuser`, UID `13370`, GID `13370`) within an isolated Docker bridge network (`172.28.0.0/16`).

---

## MITRE ATT&CK Mitigation Matrix

| Technique ID | Technique Name | Attack Scenario | Enforced Mitigation Control |
|:---|:---|:---|:---|
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Spawning `/bin/dash` or `/bin/sh` following web RCE injection | In-kernel eBPF `sys_execve` kprobe triggers synchronous `SIGKILL` |
| **T1071.004** | Application Layer Protocol: DNS | Tunnelling Base64/Hex exfiltration chunks over port 53 | Real-time Shannon Entropy proxy sinkholes queries with `NXDOMAIN` |
| **T1048.003** | Exfiltration Over Alternative Protocol | Bypassing boundary firewalls via unmonitored DNS lookups | UDP port 53 payload inspection and sliding-window velocity controls |
| **T1105** | Ingress Tool Transfer | Downloading secondary rootkits or staging scripts via `wget` | Declarative TracingPolicy terminates binary execution instantly |
| **T1049** | System Network Connections Discovery | Establishing reverse TCP tunnels via Netcat (`nc`) | Kernel hooks block resolved binaries (`/usr/bin/nc.openbsd`) |

---

## Prerequisites

* **Operating System:** Linux (Ubuntu 22.04 LTS / Ubuntu 24.04 LTS recommended, `x86_64`)
* **Linux Kernel:** $\ge 5.15$ with BPF Type Format (BTF) compiled in:
  ```bash
  # Verify BTF support exists
  ls -lh /sys/kernel/btf/vmlinux
  ```
* **Container Engine:** Docker Engine $\ge 24.0$ with Docker Compose v2 (`docker compose`)
* **Host Dependencies:** `curl`, `python3`, `bash`

---

## Quickstart

### 1. Clone & Navigate to Repository
```bash
git clone https://github.com/Paranjoy-Bordoloi/ebpf-cloud-runtime-guard.git
cd ebpf-cloud-runtime-guard
```

### 2. Build and Launch the Stack
```bash
docker compose up -d --build
```

### 3. Verify Service Health
```bash
docker compose ps
```
All three containers should be `Up`:
* `cloud-workload-app`: Flask microservice on `172.28.0.100:8080`
* `dns-entropy-monitor`: Behavioral DNS defense proxy on `172.28.0.53:53`
* `tetragon`: Privileged eBPF runtime agent with host PID access

---

## Red-Team Attack Simulation & Verification

The repository includes automated test harnesses simulating real-world attack chains:

### Test Suite A: RCE Post-Exploitation & Kernel Enforcement
Simulates an unauthenticated attacker exploiting a diagnostic endpoint to spawn interactive shells and reverse-shell primitives:
```bash
chmod +x ./attacks/simulate_exec.sh
./attacks/simulate_exec.sh
```
**Expected Output:**
* Benign requests (`GET /api/v1/health`, `GET /api/v1/tenants`) return HTTP 200 OK.
* Exploitation payloads (`/bin/dash`, `/bin/sh`, `/usr/bin/nc`, `/usr/bin/wget`) are terminated with exit code `-9` (SIGKILL / 137).
* Enforcement is verified with 100% pass rate.

### Test Suite B: Covert DNS Exfiltration Defense
Simulates DNS tunneling tools (e.g., `dnscat2`, `iodine`) encoding credit cards, API keys, and database secrets into DNS query labels:
```bash
python3 ./attacks/simulate_dns_exfil.py
```
**Expected Output:**
* Normal enterprise domains (`api.stripe.com`, `github.com`) have low entropy ($H(X) < 2.6$) and are forwarded upstream to `8.8.8.8`.
* Base64 exfiltration chunks ($H(X) \ge 3.8$) and Hexadecimal payloads ($H(X) \ge 2.8, L \ge 30$) are sinkholed with synthesized `NXDOMAIN` responses.

---

## Forensic Telemetry & Log Inspection

Inspect enriched forensic records generated in real time at `/var/log/tetragon/dns_alerts.json`:
```bash
docker exec -it dns-entropy-monitor cat /var/log/tetragon/dns_alerts.json | tail -n 1 | python3 -m json.tool
```

### Sample Enriched Forensic Record:
```json
{
  "timestamp": "2026-10-24T08:35:12.198271+00:00",
  "query": "Q0MtNDUzMi04OTIxLTk5MjMtMTEwMg.01.tunnel.evil-c2.org",
  "leftmost_label": "Q0MtNDUzMi04OTIxLTk5MjMtMTEwMg",
  "entropy": 4.0981,
  "label_length": 30,
  "burst_count": 4,
  "action": "SINKHOLED",
  "correlated_process": {
    "binary": "/usr/local/bin/python3",
    "pid": 7,
    "uid": 13370,
    "syscall": "udp_sendmsg"
  }
}
```

---

## Mathematical Formulation: Shannon Entropy Detection

Claude Shannon's information entropy $H(X)$ measures the randomness and information density of characters within a domain label string:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where:
* $L$ is the total length of the leftmost label.
* $n$ is the count of unique symbols.
* $P(x_i) = \frac{\text{count}(x_i)}{L}$ is the empirical probability of symbol $x_i$.
* $H(X)$ is quantified in **bits per character**.

### Multi-Clause Decision Heuristic:
$$\text{Verdict} \iff (H(X) \ge 3.8 \wedge L \ge 16) \vee (H(X) \ge 2.8 \wedge L \ge 30) \vee (L \ge 50)$$

* **Clause 1 ($H \ge 3.8, L \ge 16$):** Catches dense Base64 / high-alphabet encrypted tunnels.
* **Clause 2 ($H \ge 2.8, L \ge 30$):** Catches Hexadecimal encoding, which is mathematically capped at $H_{\max} = \log_2(16) = 4.0$ bits/char.
* **Clause 3 ($L \ge 50$):** Flags abnormally long labels approaching the RFC-1035 limit (63 characters).

---

## Engineering Edge Cases Solved

1. **Host DNS Port Collision:**  
   Ubuntu's local `systemd-resolved` occupies `127.0.0.53:53`. Binding host port 53 fails. Resolved by isolating the DNS daemon on static bridge IP `172.28.0.53` and routing the application container internally (`dns: 172.28.0.53`).
2. **VirtualBox Multi-Kprobe Incompatibility (`EINVAL`):**  
   Kernel 6.x virtualization under VirtualBox can fail on multi-kprobe batch attachments. Resolved by running the Tetragon daemon with `--disable-kprobe-multi=true`.
3. **Debian Symlink Evasion on Netcat:**  
   `update-alternatives` links `/usr/bin/nc` to `/usr/bin/nc.openbsd`. Added `/usr/bin/nc.openbsd` and `/bin/nc.openbsd` to the eBPF policy to block the resolved binary.
4. **RFC-1035 Label Limits:**  
   RFC 1035 restricts DNS labels to 63 octets. Exfiltration chunks are limited to 40 characters to match real-world tunneling utilities (e.g., `iodine`, `dnscat2`).

---

## Repository Structure

```text
ebpf-cloud-runtime-guard/
├── app/
│   ├── Dockerfile             # Multi-stage Docker build, non-root user (UID 13370)
│   ├── app.py                 # Multi-tenant Flask API with diagnostics endpoint
│   └── requirements.txt       # Flask, Gunicorn
├── ebpf/
│   └── tracing_policy.yaml    # Cilium Tetragon eBPF TracingPolicy (sys_execve Sigkill)
├── monitor/
│   ├── Dockerfile             # Python 3.11 UDP DNS proxy container
│   ├── dns_entropy_detector.py# Shannon Entropy calculation and telemetry correlation
│   └── requirements.txt       # dnspython
├── attacks/
│   ├── simulate_exec.sh       # Red-team automated RCE exploit test harness
│   └── simulate_dns_exfil.py  # Covert DNS exfiltration simulation suite
├── docs/
│   └── ARCHITECTURE.md        # Comprehensive technical architecture & design specs
├── docker-compose.yml         # Container orchestration and bridge network definition
├── .gitignore                 # Build and environment exclusions
└── README.md                  # Project documentation
```

---

## License

This project is licensed under the [MIT License](LICENSE).
