import os
import sys
import socket
import shlex
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

TENANT_DATABASE = [
    {
        "tenant_id": "tenant-corp-alpha",
        "organization": "Alpha Financial Services",
        "plan_tier": "enterprise",
        "assigned_subnet": "10.240.10.0/24",
        "api_credential_id": "cred_live_9948271049281729",
        "secret_token": "sk_live_sec_alpha_993847291048572019"
    },
    {
        "tenant_id": "tenant-health-beta",
        "organization": "Beta Health Informatics",
        "plan_tier": "enterprise-plus",
        "assigned_subnet": "10.240.20.0/24",
        "api_credential_id": "cred_live_1182740192837461",
        "secret_token": "sk_live_sec_beta_182930491827364510"
    },
    {
        "tenant_id": "tenant-retail-gamma",
        "organization": "Gamma Global Logistics",
        "plan_tier": "standard",
        "assigned_subnet": "10.240.30.0/24",
        "api_credential_id": "cred_live_5548392019284756",
        "secret_token": "sk_live_sec_gamma_554839201928374615"
    }
]

@app.route("/api/v1/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "cloud-workload-api",
        "hostname": socket.gethostname(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "pid": os.getpid(),
        "runtime": "python-flask",
        "kernel_enforcement_target": True
    }), 200

@app.route("/api/v1/tenants", methods=["GET"])
def list_tenants():
    return jsonify({
        "status": "success",
        "total_tenants": len(TENANT_DATABASE),
        "tenants": TENANT_DATABASE
    }), 200

@app.route("/api/v1/diagnostics", methods=["POST"])
def run_diagnostics():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({
            "status": "error",
            "message": "Malformed or missing JSON payload"
        }), 400

    if "cmd" in payload:
        cmd_raw = payload.get("cmd")
        if not cmd_raw:
            return jsonify({
                "status": "error",
                "message": "Field 'cmd' cannot be empty"
            }), 400

        try:
            tokens = shlex.split(cmd_raw) if isinstance(cmd_raw, str) else list(cmd_raw)
            if not tokens:
                return jsonify({
                    "status": "error",
                    "message": "No command arguments parsed"
                }), 400

            target_binary = tokens[0]
            if os.path.exists(target_binary):
                resolved_binary = os.path.realpath(target_binary)
                execution_args = [resolved_binary] + tokens[1:]
            else:
                execution_args = tokens

            proc = subprocess.run(
                execution_args,
                capture_output=True,
                text=True,
                timeout=5
            )

            is_kernel_killed = proc.returncode in (-9, 137)

            return jsonify({
                "status": "enforced" if is_kernel_killed else "completed",
                "command": cmd_raw,
                "executed_binary": execution_args[0],
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "enforced_by_kernel": is_kernel_killed
            }), 200

        except subprocess.TimeoutExpired as exc:
            return jsonify({
                "status": "timeout",
                "command": cmd_raw,
                "error": str(exc),
                "enforced_by_kernel": False
            }), 408

        except FileNotFoundError as exc:
            return jsonify({
                "status": "not_found",
                "command": cmd_raw,
                "error": str(exc),
                "enforced_by_kernel": False
            }), 404

        except Exception as exc:
            return jsonify({
                "status": "error",
                "command": cmd_raw,
                "error": str(exc),
                "enforced_by_kernel": False
            }), 500

    elif "lookup" in payload:
        lookup_host = payload.get("lookup")
        if not lookup_host:
            return jsonify({
                "status": "error",
                "message": "Field 'lookup' cannot be empty"
            }), 400

        clean_host = lookup_host.strip().rstrip(".")
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            resolved_ips = sorted(list(set(info[4][0] for info in addr_info)))
            is_sinkholed = resolved_ips == ["0.0.0.0"]

            return jsonify({
                "status": "sinkholed" if is_sinkholed else "resolved",
                "query": clean_host,
                "resolved_ips": resolved_ips,
                "sinkholed": is_sinkholed
            }), 200

        except socket.gaierror as exc:
            return jsonify({
                "status": "lookup_failed",
                "query": clean_host,
                "error": str(exc),
                "sinkholed": True
            }), 200

        except Exception as exc:
            return jsonify({
                "status": "error",
                "query": clean_host,
                "error": str(exc),
                "sinkholed": False
            }), 500

    else:
        return jsonify({
            "status": "error",
            "message": "Payload must contain either 'cmd' or 'lookup'"
        }), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
