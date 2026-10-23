import os
import sys
import time
import math
import json
import socket
import threading
import collections
import datetime
import dns.message
import dns.query
import dns.rcode

TETRAGON_LOG_PATH = "/var/log/tetragon/tetragon.log"
ALERTS_LOG_PATH = "/var/log/tetragon/dns_alerts.json"
BIND_HOST = "0.0.0.0"
BIND_PORT = 53
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53
ENTROPY_THRESHOLD = 3.8
LENGTH_THRESHOLD = 16
VELOCITY_WINDOW_SECONDS = 5.0
VELOCITY_BURST_THRESHOLD = 10

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[1;31m"
COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[1;36m"
COLOR_MAGENTA = "\033[1;35m"

class KernelTelemetryCorrelator:
    def __init__(self, log_path):
        self.log_path = log_path
        self.lock = threading.Lock()
        self.latest_process_info = {
            "binary": "cloud-workload-python",
            "pid": 13370,
            "uid": 13370,
            "syscall": "udp_sendmsg",
            "timestamp": None
        }
        self.running = True

    def start(self):
        worker = threading.Thread(target=self._tail_log, daemon=True)
        worker.start()

    def _tail_log(self):
        while self.running:
            if not os.path.exists(self.log_path):
                time.sleep(1.0)
                continue

            try:
                with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while self.running:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue

                        self._process_line(line.strip())
            except Exception:
                time.sleep(1.0)

    def _process_line(self, line):
        if not line:
            return
        try:
            event = json.loads(line)
            proc_info = None

            if "process_kprobe" in event:
                kp = event.get("process_kprobe", {})
                proc_info = kp.get("process", {})
                func_name = kp.get("function_name", "kprobe")
            elif "process_exec" in event:
                pe = event.get("process_exec", {})
                proc_info = pe.get("process", {})
                func_name = "sys_execve"
            elif "process" in event:
                proc_info = event.get("process", {})
                func_name = "event"

            if proc_info:
                with self.lock:
                    self.latest_process_info = {
                        "binary": proc_info.get("binary", "cloud-workload-python"),
                        "pid": proc_info.get("pid", 13370),
                        "uid": proc_info.get("uid", 13370),
                        "syscall": func_name,
                        "timestamp": event.get("time", datetime.datetime.now(datetime.timezone.utc).isoformat())
                    }
        except Exception:
            return

    def get_correlation(self):
        with self.lock:
            return dict(self.latest_process_info)

class DNSEntropyDetector:
    def __init__(self):
        self.correlator = KernelTelemetryCorrelator(TETRAGON_LOG_PATH)
        self.velocity_lock = threading.Lock()
        self.velocity_history = collections.defaultdict(list)
        self.alerts_file_lock = threading.Lock()

    def compute_shannon_entropy(self, label):
        if not label:
            return 0.0
        length = len(label)
        frequencies = collections.Counter(label)
        entropy = 0.0
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_leftmost_label(self, qname):
        cleaned = qname.strip().rstrip(".")
        parts = cleaned.split(".")
        return parts[0] if parts else ""

    def extract_base_domain(self, qname):
        cleaned = qname.strip().rstrip(".")
        parts = cleaned.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return cleaned

    def check_velocity(self, base_domain, client_ip):
        now = time.time()
        key = f"{client_ip}:{base_domain}"
        with self.velocity_lock:
            history = self.velocity_history[key]
            cutoff = now - VELOCITY_WINDOW_SECONDS
            filtered = [ts for ts in history if ts >= cutoff]
            filtered.append(now)
            self.velocity_history[key] = filtered
            return len(filtered)

    def log_alert(self, alert_data):
        log_dir = os.path.dirname(ALERTS_LOG_PATH)
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                pass

        with self.alerts_file_lock:
            try:
                with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_data) + "\n")
            except Exception:
                pass

    def inspect_query(self, qname, client_ip):
        leftmost = self.extract_leftmost_label(qname)
        base_domain = self.extract_base_domain(qname)
        entropy = self.compute_shannon_entropy(leftmost)
        label_len = len(leftmost)
        burst_count = self.check_velocity(base_domain, client_ip)

        is_entropy_anomaly = (entropy >= ENTROPY_THRESHOLD and label_len >= LENGTH_THRESHOLD)
        is_velocity_anomaly = (burst_count >= VELOCITY_BURST_THRESHOLD)
        is_exfiltration = is_entropy_anomaly or is_velocity_anomaly

        correlated_proc = self.correlator.get_correlation()

        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "query": qname.strip().rstrip("."),
            "leftmost_label": leftmost,
            "entropy": entropy,
            "label_length": label_len,
            "burst_count": burst_count,
            "client_ip": client_ip,
            "verdict": "COVERT_EXFIL_DETECTED" if is_exfiltration else "BENIGN",
            "detection_reason": (
                "HIGH_SHANNON_ENTROPY" if is_entropy_anomaly else
                ("BURST_FREQUENCY_THRESHOLD" if is_velocity_anomaly else "NORMAL_RESOLUTION")
            ),
            "action": "SINKHOLED_NXDOMAIN" if is_exfiltration else "FORWARDED_UPSTREAM",
            "correlated_process": correlated_proc
        }

        if is_exfiltration:
            self.log_alert(record)
            print(
                f"{COLOR_RED}[COVERT_EXFIL_DETECTED]{COLOR_RESET} "
                f"Domain: {COLOR_YELLOW}{record['query']}{COLOR_RESET} | "
                f"Entropy: {COLOR_MAGENTA}{entropy:.3f}{COLOR_RESET} | "
                f"Len: {label_len} | Burst: {burst_count} | "
                f"Action: {COLOR_RED}SINKHOLED{COLOR_RESET} | "
                f"Proc: {correlated_proc['binary']}:{correlated_proc['pid']} (UID:{correlated_proc['uid']})",
                flush=True
            )
        else:
            print(
                f"{COLOR_GREEN}[BENIGN]{COLOR_RESET}                 "
                f"Domain: {COLOR_CYAN}{record['query']}{COLOR_RESET} | "
                f"Entropy: {entropy:.3f} | Len: {label_len} | "
                f"Action: {COLOR_GREEN}FORWARDED{COLOR_RESET} | "
                f"Proc: {correlated_proc['binary']}:{correlated_proc['pid']}",
                flush=True
            )

        return is_exfiltration

    def run(self):
        self.correlator.start()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND_HOST, BIND_PORT))

        print(
            f"{COLOR_CYAN}[DNS_DEFENSE_DAEMON_INITIALIZED]{COLOR_RESET} "
            f"Listening on {BIND_HOST}:{BIND_PORT} | Upstream: {UPSTREAM_DNS}:{UPSTREAM_PORT} | "
            f"Entropy Threshold: {ENTROPY_THRESHOLD} | Min Length: {LENGTH_THRESHOLD}",
            flush=True
        )

        while True:
            try:
                data, client_addr = sock.recvfrom(4096)
                if not data:
                    continue

                try:
                    query_msg = dns.message.from_wire(data)
                except Exception:
                    continue

                if not query_msg.question:
                    continue

                qname = query_msg.question[0].name.to_text()
                is_malicious = self.inspect_query(qname, client_addr[0])

                if is_malicious:
                    sinkhole_resp = dns.message.make_response(query_msg)
                    sinkhole_resp.set_rcode(dns.rcode.NXDOMAIN)
                    sock.sendto(sinkhole_resp.to_wire(), client_addr)
                else:
                    try:
                        upstream_resp = dns.query.udp(query_msg, UPSTREAM_DNS, port=UPSTREAM_PORT, timeout=2.5)
                        sock.sendto(upstream_resp.to_wire(), client_addr)
                    except Exception:
                        fallback_resp = dns.message.make_response(query_msg)
                        fallback_resp.set_rcode(dns.rcode.NXDOMAIN)
                        sock.sendto(fallback_resp.to_wire(), client_addr)

            except Exception as err:
                print(f"[DAEMON_EXCEPTION] {err}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    detector = DNSEntropyDetector()
    detector.run()
