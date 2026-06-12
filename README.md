# endpoint-security-ca1

**Endpoint Security Incident Response and Automated Remediation**  
CA1 Assessment — Communication and Network Security (B9CY110)  
MSc Cybersecurity — Dublin Business School  
Student: Akhil Alex (20093197)

---

## Overview

This repository contains the Dockerised AI security stack built as part of CA1 for the Communication and Network Security module at Dublin Business School.

The stack monitors a Wazuh SIEM alert feed in real time, applies AI-assisted triage, and triggers predefined automated remediation actions against detected threats. It was built and tested in an isolated VirtualBox lab environment simulating a breach at a fictitious organisation called **Larkspur Retail Group**.

---

## Repository Structure

```
endpoint-security-ca1/
├── docker-compose.yml          # Full stack definition
├── allowlist.json              # Permitted remediation actions
├── alert-processor/
│   ├── Dockerfile
│   └── main.py                 # Alert polling, AI triage, action dispatch
├── remediation-engine/
│   ├── Dockerfile
│   └── app.py                  # Flask API — executes allowlisted actions
├── audit-log/                  # Created at runtime — stores remediation.log
└── README.md
```

---

## Lab Environment

| Host | Role | IP Address | OS | Wazuh Agent |
|------|------|------------|----|-------------|
| akhil-VirtualBox | Wazuh SIEM Server + Docker Host | 10.0.3.15/24 | Ubuntu 22.04 LTS | Manager |
| kali | Linux Endpoint | 10.0.3.20/24 | Kali GNU/Linux 2026.1 | Agent 002 |
| windows-endpoint | Windows Endpoint | 10.0.3.30/24 | Windows 10 Pro 10.0.19045 | Agent 003 |

- **Network:** VirtualBox Internal Network — 10.0.3.0/24 (isolated, no public internet)
- **SIEM:** Wazuh v4.7.5
- **NTP:** Active, Europe/Dublin (UTC+1)

---

## Stack Architecture

```
[ windows-endpoint ]          [ kali ]
  10.0.3.30                     10.0.3.20
  Wazuh Agent 003               Wazuh Agent 002
        |  port 1514 UDP               |
        +--------------+---------------+
                       |
         [ Wazuh Server — 10.0.3.15 ]
           Wazuh Manager + Dashboard
                       |
         /var/ossec/logs/alerts/alerts.json
                  (read-only mount)
                       |
     [ Docker: security-net bridge 172.18.0.0/16 ]
        |                              |
[ alert-processor ]        [ remediation-engine ]
  Polls alerts.json          Flask API — port 5000
  AI triage + allowlist      Executes: disable_user
  Writes audit log           Executes: block_ip
                             Returns rollback command
```

---

## Components

### alert-processor

- Polls `/wazuh-alerts/alerts.json` every 10 seconds
- Filters alerts with `rule.level >= 7`
- Applies `summarise_alert()` for AI-style triage summary
- Applies `decide_remediation()` to determine action based on severity, description keywords, and source IP
- Forwards qualifying actions via HTTP POST to the remediation-engine
- Logs all actions to `/audit-log/remediation.log`

### remediation-engine

- Flask API running on port 5000
- Validates incoming actions against `allowlist.json` before execution
- Executes `disable_user` via `usermod -L <username>`
- Executes `block_ip` via `iptables -I INPUT -s <ip> -j DROP`
- Returns rollback command in response (`usermod -U <username>` / `iptables -D INPUT -s <ip> -j DROP`)
- Logs all actions with timestamp and status to shared audit volume

### Allowlisted Actions

Only the following actions are permitted — no unrestricted command execution:

```json
["block_ip", "disable_user"]
```

---

## Security Controls

| Control | Implementation |
|---------|---------------|
| Read-only SIEM data | `/var/ossec/logs/alerts` mounted `:ro` |
| Read-only allowlist | `allowlist.json` mounted `:ro` |
| No privileged containers | Only `NET_ADMIN` cap on remediation-engine for iptables |
| Isolated network | `security-net` bridge — no internet exposure |
| Audit trail | All actions logged to `audit-log/remediation.log` |
| Rollback | Every action returns a verified rollback command |

---

## Prerequisites

- Docker and Docker Compose installed on the Wazuh server
- Wazuh manager running with alerts being written to `/var/ossec/logs/alerts/alerts.json`
- User running Docker must have sudo or docker group membership

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/alexdbsie/endpoint-security-ca1.git
cd endpoint-security-ca1

# 2. Start the full stack
sudo docker-compose up -d

# 3. Confirm both containers are running
sudo docker-compose ps

# 4. Run alert processor with live output (for demo/testing)
sudo docker-compose run --rm \
  -e PYTHONUNBUFFERED=1 \
  alert-processor python -u main.py 2>&1 | head -50
```

Expected output:
```
[*] Alert processor started, monitoring: /wazuh-alerts/alerts.json
[ALERT L9] [AI Summary] Level 9 alert on kali: SCA summary...
[ALERT L8] [AI Summary] Level 8 alert on kali: New user added to the system.
[ACTION] {'action': 'disable_user', 'target': 'ntpsec', 'reason': 'new user added to the system.'}
[AUDIT] {'time': '2026-06-12T10:37:44.843372', 'action': 'disable_user', 'target': 'ntpsec',
         'status': 'SUCCESS', 'response': '{"rollback":"usermod -U ntpsec","status":"success"}'}
```

---

## Remediation Playbooks

### Playbook 1 — disable_user

| Field | Detail |
|-------|--------|
| Trigger | Rule 5902 (new user added), level ≥ 8, `useradd` or `new user` in description |
| Target | `dstuser` field from Wazuh alert |
| Action | `usermod -L <username>` — locks the account |
| Verification | AUDIT log entry with `status: SUCCESS` |
| Rollback | `usermod -U <username>` — unlocks the account |

### Playbook 2 — block_ip

| Field | Detail |
|-------|--------|
| Trigger | Level ≥ 8, `brute` or `authentication failure` in description, valid `srcip` present |
| Target | `srcip` field from Wazuh alert |
| Action | `iptables -I INPUT -s <ip> -j DROP` |
| Verification | AUDIT log entry with `status: SUCCESS` |
| Rollback | `iptables -D INPUT -s <ip> -j DROP` |

---

## MITRE ATT&CK Detection Coverage

| Rule ID | Description | Level | Technique | Tactic |
|---------|-------------|-------|-----------|--------|
| 5902 | New user added to system | 8 | T1136.001 — Create Local Account | Persistence |
| 5901 | New group added to system | 8 | T1069 — Permission Groups Discovery | Discovery |
| 60112 | Windows audit policy changed | 8 | T1562.002 — Disable Windows Event Logging | Defense Evasion |
| 60602 | Windows application error event | 9 | T1499 — Endpoint Denial of Service | Impact |
| 19004 | CIS Windows 10 Benchmark score < 50% | 7 | T1562.001 — Disable or Modify Tools | Defense Evasion |
| 550 | Integrity checksum changed (FIM) | 7 | T1565.001 — Stored Data Manipulation | Impact |
| 19007 | CIS Windows Benchmark control failure | 7 | T1078 — Valid Accounts | Initial Access |

---

## Stopping and Cleanup

```bash
# Stop the stack
sudo docker-compose down

# View audit log
cat audit-log/remediation.log

# Roll back a disabled user manually
sudo usermod -U <username>

# Roll back a blocked IP manually
sudo iptables -D INPUT -s <ip> -j DROP
```

---

## Ethical and Safety Notes

- No real malware was used at any point
- The lab network is fully isolated — no services exposed to public networks
- All remediation actions are reversible
- The stack has no unrestricted command execution — all actions are predefined and allowlisted

---

## References

- Wazuh Documentation: https://documentation.wazuh.com
- MITRE ATT&CK: https://attack.mitre.org
- CIS Controls v8: https://www.cisecurity.org/controls/v8
- NIST SP 800-61 Rev 2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- CIS Windows 10 Benchmark: https://www.cisecurity.org/benchmark/microsoft_windows_desktop

---

## Licence

This repository is submitted as academic coursework for Dublin Business School. Not for commercial use.
