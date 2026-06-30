# Incident Response Playbooks

## Playbook 1 — Brute Force (SOAR-002)

**Trigger:** SIEM-001 detects ≥5 failed auth attempts from same IP in 10 minutes (FSM).

```
DETECTION  → SIEM-001 threshold breach → alert to ORCH-000
TRIAGE     → ORCH-000 dedup + DB insert + route to SOAR-002
ENRICHMENT → VirusTotal IP lookup + AbuseIPDB confidence score
NOTIFY     → WhatsApp/SMS to L1 analyst with enrichment summary + OTP
DECISION   → Analyst replies: YES / NO / ESCALATE (SLA: 15 min)
CONTAIN    → YES: block IP via SIM-004 firewall + close incident
ESCALATE   → No response after 15 min: TIMEOUT-008 → L2 analyst
```

## Playbook 2 — Phishing (SOAR-003)

**Trigger:** Email gateway or manual report → webhook to SOAR-003.

```
TRIAGE    → Parse alert, extract indicators, notify L1 + OTP
DECISION  → Analyst: ISOLATE / IGNORE / ESCALATE (SLA: 15 min)
CONTAIN   → ISOLATE triggers 3 parallel actions:
            · SIM-004: isolate host from network
            · SIM-004: purge emails from malicious sender
            · SIM-004: trigger AV/EDR scan on host
ESCALATE  → TIMEOUT-008 detects breach → L2 WhatsApp
```

## SLA Policy

| Incident | L1 SLA | Auto-Escalate |
|----------|--------|---------------|
| Brute Force | 15 min | Yes — TIMEOUT-008 |
| Phishing | 15 min | Yes — TIMEOUT-008 |

## KPIs (REPORT-005)

- MTTD — Mean Time to Detect
- MTTR — Mean Time to Respond
- Incidents by type and severity
- Analyst response rate within SLA
- Auto-escalation rate
