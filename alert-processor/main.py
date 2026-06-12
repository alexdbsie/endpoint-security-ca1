import json, os, time, requests
from datetime import datetime

ALERT_FILE = os.getenv("WAZUH_ALERT_FILE", "/wazuh-alerts/alerts.json")
AUDIT_LOG = os.getenv("AUDIT_LOG", "/audit-log/remediation.log")
REMEDIATION_URL = "http://remediation-engine:5000/remediate"

ALLOWLISTED_ACTIONS = ["block_ip", "disable_user"]

def log_audit(entry):
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[AUDIT] {entry}")

def summarise_alert(alert):
    desc = alert.get("rule", {}).get("description", "Unknown")
    level = alert.get("rule", {}).get("level", 0)
    agent = alert.get("agent", {}).get("name", "unknown")
    return f"[AI Summary] Level {level} alert on {agent}: {desc}"

def decide_remediation(alert):
    level = int(alert.get("rule", {}).get("level", 0))
    desc = alert.get("rule", {}).get("description", "").lower()
    src_ip = alert.get("data", {}).get("srcip", "")
    if level >= 8 and ("brute" in desc or "authentication failure" in desc):
        if src_ip and src_ip not in ["127.0.0.1", "::1", ""]:
            return {"action": "block_ip", "target": src_ip, "reason": desc}
    if "useradd" in desc or "new user" in desc:
        user = alert.get("data", {}).get("dstuser", "")
        if user and user not in ["root", "akhil"]:
            return {"action": "disable_user", "target": user, "reason": desc}
    return None

def trigger_remediation(action_data, summary):
    if action_data["action"] not in ALLOWLISTED_ACTIONS:
        log_audit({"time": datetime.now().isoformat(), "status": "BLOCKED", "action": action_data})
        return
    entry = {"time": datetime.now().isoformat(), "action": action_data["action"],
             "target": action_data["target"], "ai_summary": summary, "status": "TRIGGERED"}
    try:
        r = requests.post(REMEDIATION_URL, json=action_data, timeout=5)
        entry["status"] = "SUCCESS" if r.status_code == 200 else "FAILED"
        entry["response"] = r.text
    except Exception as e:
        entry["status"] = "ERROR"
        entry["error"] = str(e)
    log_audit(entry)

def process_alerts():
    print("[*] Alert processor started, monitoring:", ALERT_FILE)
    seen = set()
    while True:
        try:
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line in seen:
                            continue
                        seen.add(line)
                        try:
                            alert = json.loads(line)
                            level = int(alert.get("rule", {}).get("level", 0))
                            if level >= 7:
                                summary = summarise_alert(alert)
                                print(f"[ALERT L{level}] {summary}")
                                action = decide_remediation(alert)
                                if action:
                                    print(f"[ACTION] {action}")
                                    trigger_remediation(action, summary)
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            print(f"[ERROR] {e}")
        time.sleep(10)

if __name__ == "__main__":
    process_alerts()
