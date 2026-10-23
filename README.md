# eBPF-Enforced Kernel Runtime Security and Covert DNS Exfiltration Defense for Cloud Workloads

A production-grade cloud-native runtime security system built with **Cilium Tetragon eBPF** kernel instrumentation, an in-kernel **Sigkill** execution enforcement policy, and an asynchronous **Shannon Entropy DNS Exfiltration Defense Daemon**.

---

## 1. Project Overview & Evaluation Rubric Alignment

This project is built for an academic B.Tech Mini Project evaluation adhering strictly to university rubrics:

| Evaluation Rubric | Allocated Marks | Delivered Artifacts & Verification |
|:---|:---|:---|
| **1. Technical Implementation** | **10 Marks** | Production eBPF `TracingPolicy` intercepting `sys_execve`, `udp_sendmsg`, and `tcp_connect`; non-root containerized Flask workload (`UID 13370`); real-time Shannon Entropy ($H(X)$) DNS detection engine with zero mock/stub code. |
| **2. Resource Deployment & Live Demo** | **5 Marks** | Reproducible multi-container Docker Compose topology; deterministic kernel `Sigkill` enforcement without crashing the host VM; automated red-team attack harnesses with formatted terminal output. |
| **3. Documentation & Viva Defense** | **10 Marks** | Comprehensive dual-plane system architecture diagrams (`docs/ARCHITECTURE.md`); full mathematical formulation of entropy detection; 15-question examiner Viva cheatsheet (`docs/VIVA_CHEATSHEET.md`). |

---

## 2. System Prerequisites

The system is designed for bare-metal or virtualized Linux environments:
- **Operating System:** Ubuntu 22.04 LTS or Ubuntu 24.04 LTS (`x86_64`).
- **Linux Kernel:** Version $\ge 5.15$ with BPF Type Format (BTF) compiled in:
  Verify kernel BTF support:
  ```bash
  ls -lh /sys/kernel/btf/vmlinux
  ```
- **Container Engine:** Docker Engine $\ge 24.0$ with Docker Compose v2 (`docker compose`).
- **Utilities:** `curl`, `python3`, `bash`.

---

## 3. Repository Structure

```text
ebpf-cloud-runtime-guard/
├── app/
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
├── ebpf/
│   └── tracing_policy.yaml
├── monitor/
│   ├── Dockerfile
│   ├── dns_entropy_detector.py
│   └── requirements.txt
├── attacks/
│   ├── simulate_exec.sh
│   └── simulate_dns_exfil.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── VIVA_CHEATSHEET.md
├── docker-compose.yml
└── README.md
```

---

## 4. Quickstart Deployment Guide

### Step 1: Verify Host Kernel BTF Support
```bash
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "[OK] BTF enabled at /sys/kernel/btf/vmlinux"
else
    echo "[ERROR] Kernel BTF not found. Please upgrade to Linux Kernel >= 5.15"
fi
```

### Step 2: Build and Launch the Stack
From the `ebpf-cloud-runtime-guard/` root directory:
```bash
docker compose up -d --build
```

### Step 3: Verify All Containers Are Healthy
```bash
docker compose ps
```
Expected status:
```text
NAME                  IMAGE                           COMMAND                  SERVICE      STATUS
cloud-workload-app    ebpf-cloud-runtime-guard-app    "gunicorn --bind 0.0…"   app          Up
dns-entropy-monitor   ebpf-cloud-runtime-guard-monitor "python dns_entropy_…"   monitor      Up
tetragon              quay.io/cilium/tetragon:v1.1.0  "/usr/bin/tetragon -…"   tetragon     Up
```

---

## 5. Live Demonstration Walkthrough (3-Terminal Setup)

For university evaluators and viva defense, open three parallel terminal windows to showcase real-time kernel interception, network telemetry, and attack execution.

### Terminal 1: Kernel-Space eBPF Event Stream (Tetragon)
Stream live eBPF kernel enforcement events:
```bash
docker exec -it tetragon tetra getevents -o compact
```
*(Alternative: tail the raw JSON export log directly)*
```bash
docker exec -it tetragon tail -f /var/log/tetragon/tetragon.log | grep -E "sys_execve|udp_sendmsg"
```

### Terminal 2: Userspace DNS Shannon Entropy Defense Daemon
Observe real-time DNS telemetry, entropy calculations, process attribution, and sinkholing actions:
```bash
docker logs -f dns-entropy-monitor
```

### Terminal 3: Red-Team Attack Simulation Harnesses

#### Test Suite A: RCE & Kernel Execution Enforcement
Execute the automated execution test suite against the workload:
```bash
chmod +x ./attacks/simulate_exec.sh
./attacks/simulate_exec.sh
```

**What Evaluators See:**
1. Baseline `GET /api/v1/health` and `GET /api/v1/tenants` return `HTTP 200` successfully.
2. Exploit payloads attempting to spawn `/bin/dash`, `/bin/sh`, `/usr/bin/nc`, and `/usr/bin/wget` are intercepted synchronously in kernel space.
3. The child processes are terminated with `SIGKILL` (signal 9 / returncode -9 / exit 137).
4. Terminal 1 displays synchronous `SIGKILL` event notifications emitted by the eBPF kprobe.

#### Test Suite B: Covert DNS Exfiltration Defense
Execute the automated DNS exfiltration simulation:
```bash
python3 ./attacks/simulate_dns_exfil.py
```

**What Evaluators See:**
1. Legitimate domains (`api.stripe.com`, `auth.internal.cloud`) exhibit low Shannon Entropy ($H(X) \approx 1.5 - 2.5$) and are forwarded upstream to `8.8.8.8`.
2. Covert tunneling queries carrying synthetic tenant credit cards, API keys, and AWS secrets encoded in Base64/Hex exhibit high entropy ($H(X) \ge 3.8$) and long labels ($\ge 16$).
3. The defense daemon sinkholes exfiltration queries with `NXDOMAIN`, preventing data leakage while logging structured attribution records to `/var/log/tetragon/dns_alerts.json`.

---

## 6. Verification & Telemetry Inspection Commands

### Inspect Generated DNS Defense Alerts
```bash
docker exec -it dns-entropy-monitor cat /var/log/tetragon/dns_alerts.json | python3 -m json.tool
```

### Test Individual Diagnostics Payload via Curl
```bash
# Test Benign Diagnostics
curl -s http://localhost:8080/api/v1/health | python3 -m json.tool

# Test Blocked Execution
curl -s -X POST http://localhost:8080/api/v1/diagnostics \
  -H "Content-Type: application/json" \
  -d '{"cmd": "/bin/dash"}' | python3 -m json.tool

# Test DNS Resolution via Workload
curl -s -X POST http://localhost:8080/api/v1/diagnostics \
  -H "Content-Type: application/json" \
  -d '{"lookup": "api.stripe.com"}' | python3 -m json.tool
```

---

## 7. Teardown
To cleanly stop and remove the containers, networks, and shared volumes:
```bash
docker compose down -v
```

---

## 8. Documentation References
- Detailed Architecture & Threat Model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Examiner Viva Questions & Defense Cheatsheet: [docs/VIVA_CHEATSHEET.md](docs/VIVA_CHEATSHEET.md)
