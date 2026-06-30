# 🛡️ SIEM/SOAR Automation Platform — n8n

> **Full-stack SOC automation** built with n8n: real-time brute force & phishing detection, automated incident response, OTP-secured analyst decisions, threat intelligence enrichment, SLA escalation, and a live SOC dashboard.

---

## 🎯 Project Overview

This project simulates a **production-grade SOC automation pipeline** handling two major incident types: **Brute Force attacks** and **Phishing campaigns**. Every component mirrors real-world Blue Team operations found in enterprise SOCs.

Built to understand how modern MSSPs automate Level 1 analyst tasks, reduce MTTD/MTTR, and enforce SLA compliance.

---

## 🏗️ Architecture

```
External Logs (Firewall / Auth / Email)
          │
          ▼
  GW-007 ─ API Gateway (Auth + Rate Limiting + Circuit Breaker)
          │
          ▼
  SIEM-001 ─ BruteForce Detector (FSM state machine, PostgreSQL)
          │ Alert triggered
          ▼
  ORCH-000 ─ Incident Dispatcher (Dedup + DB + Playbook Routing)
          │
    ┌─────┴──────┐
    ▼            ▼
SOAR-002      SOAR-003
BruteForce    Phishing
Response      Response
· VT Lookup   · Host Isolation
· AbuseIPDB   · Email Purge
· OTP Auth    · AV Scan
· FW Block    · OTP Auth
    │            │
    └─────┬──────┘
          ▼
  RESP-006 ─ Response Dispatcher (SMS routing)
  RELAY-010 ─ Twilio HMAC Validator (anti-spoofing)
  TIMEOUT-008 ─ SLA Escalation (scheduled, 15min SLA)
  REPORT-005 ─ Metrics Dashboard (MTTD / MTTR / KPIs)
```

---

## ⚙️ Workflows

| ID | Workflow | Role |
|----|----------|------|
| `SIEM-001` | BruteForce Detector | FSM-based detection, threshold: 5 failures / 10 min |
| `SOAR-002` | BruteForce Response | VirusTotal + AbuseIPDB enrichment, OTP analyst auth, IP block |
| `SOAR-003` | Phishing Response | Host isolation, email purge, AV scan, OTP approval |
| `ORCH-000` | Incident Dispatcher | Dedup, DB insert, playbook routing |
| `GW-007` | API Gateway | Token auth, rate limiting, circuit breaker |
| `RELAY-010` | Twilio HMAC Validator | HMAC-SHA1 signature verification on SMS callbacks |
| `RESP-006` | Response Dispatcher | Routes YES/NO/ESCALATE SMS to correct playbook |
| `REPORT-005` | Metrics Dashboard | Live KPIs: MTTD, MTTR, incident breakdown |
| `SIM-004` | Firewall Simulator | Simulates IP block/unblock API for lab testing |
| `TIMEOUT-008` | SLA Escalation | Scheduled check, auto-escalates to L2 after 15 min |

---

## 🔐 Security Features

- **OTP Authentication** — analyst decisions protected by time-limited OTPs (Supabase Edge Functions)
- **HMAC-SHA1 Validation** — all Twilio callbacks are signature-verified (anti-spoofing)
- **Rate Limiting** — API Gateway enforces per-IP limits
- **Circuit Breaker** — prevents cascade failures on downstream service outage
- **Incident Deduplication** — ORCH-000 prevents duplicate alerts for the same incident
- **Token-based Auth** — every inter-workflow call is authenticated

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Automation | n8n (Cloud) |
| Database | PostgreSQL (Supabase) |
| Alerting | Twilio (WhatsApp + SMS) |
| Threat Intel | VirusTotal API, AbuseIPDB |
| OTP | Supabase Edge Functions |
| Dashboard | HTML / CSS / JavaScript |

---

## 🚀 Setup

### Prerequisites
- n8n instance (Cloud or Docker self-hosted)
- PostgreSQL database (Supabase recommended)
- Twilio account (WhatsApp sandbox)
- AbuseIPDB API key (free tier)
- VirusTotal API key (free tier)

### Step 1 — Environment variables
```bash
cp .env.example .env
# Fill in your credentials
```

### Step 2 — Import workflows into n8n
```
n8n → Settings → Import Workflow → select each JSON from /workflows/
Import order:
  1. SIM-004  (infrastructure)
  2. GW-007
  3. SIEM-001
  4. ORCH-000
  5. SOAR-002
  6. SOAR-003
  7. RESP-006
  8. RELAY-010
  9. REPORT-005
  10. TIMEOUT-008
```

### Step 3 — Configure n8n credentials & variables
Add PostgreSQL, Twilio credentials and all variables from `.env.example` in n8n Settings → Variables.

### Step 4 — Activate workflows and open dashboard
Open `dashboard/soc_dashboard.html` in a browser to see live metrics.

---

## 📊 Database Schema (simplified)

```sql
CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type VARCHAR(50),          -- 'brute_force' | 'phishing'
  severity VARCHAR(20),
  source_ip INET,
  status VARCHAR(30),        -- 'open' | 'acknowledged' | 'closed' | 'escalated'
  created_at TIMESTAMPTZ DEFAULT now(),
  closed_at TIMESTAMPTZ,
  analyst_decision VARCHAR(20)
);

CREATE TABLE fsm_states (
  ip INET PRIMARY KEY,
  state VARCHAR(30),
  fail_count INTEGER DEFAULT 0,
  last_seen TIMESTAMPTZ
);

CREATE TABLE otps (
  id UUID PRIMARY KEY,
  incident_id UUID REFERENCES incidents(id),
  otp_code VARCHAR(10),
  expires_at TIMESTAMPTZ,
  used BOOLEAN DEFAULT false
);
```

---

## 🎓 What I Learned

- Designing **event-driven security architectures** with microservice-style workflows
- Implementing **Finite State Machine (FSM)** logic for stateful threat detection
- Securing inter-service calls with **HMAC signatures** and **token-based auth**
- Building **OTP multi-factor approval flows** for critical analyst actions
- Integrating **real threat intelligence APIs** into automated playbooks
- Measuring SOC performance with **MTTD** and **MTTR** KPIs

---

## ⚠️ Disclaimer

Educational project. All credentials in `.env.example` are placeholders. Never commit real API keys.

---

## 📫 Author

**[Your Name]** — Cybersecurity Student | SOC & Blue Team Enthusiast
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/your-profile)
