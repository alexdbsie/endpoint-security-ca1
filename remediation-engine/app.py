from flask import Flask, request, jsonify
import subprocess, json, os
from datetime import datetime

app = Flask(__name__)
AUDIT_LOG = "/audit-log/remediation.log"

with open("/app/allowlist.json") as f:
    ALLOWLIST = json.load(f)

def log_action(action, target, result, rollback):
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    entry = {"time": datetime.now().isoformat(), "action": action,
             "target": target, "result": result, "rollback": rollback}
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

@app.route("/remediate", methods=["POST"])
def remediate():
    data = request.json
    action = data.get("action")
    target = data.get("target")
    if action not in ALLOWLIST.get("allowed_actions", []):
        return jsonify({"status": "blocked"}), 403
    if action == "block_ip":
        rollback = f"iptables -D INPUT -s {target} -j DROP"
        try:
            subprocess.run(["iptables", "-I", "INPUT", "-s", target, "-j", "DROP"],
                         capture_output=True, timeout=10)
            log_action(action, target, "blocked", rollback)
            return jsonify({"status": "success", "rollback": rollback})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500
    if action == "disable_user":
        rollback = f"usermod -U {target}"
        try:
            subprocess.run(["usermod", "-L", target], capture_output=True, timeout=10)
            log_action(action, target, "disabled", rollback)
            return jsonify({"status": "success", "rollback": rollback})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500
    return jsonify({"status": "unknown"}), 400

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
