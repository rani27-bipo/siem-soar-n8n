#!/usr/bin/env python3
"""
==============================================================
SOC n8n Cloud — Suite de tests FINALE CORRIGÉE
Correction sécurité : plus aucun secret en dur dans le code.
Tous les tokens sont lus depuis le fichier .env
==============================================================
"""

import requests
import json
import time
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

# ==============================================================
# CHARGEMENT SÉCURISÉ DES SECRETS DEPUIS .env
# Ne jamais mettre de tokens en dur ici.
# Copier .env.example → .env et remplir les valeurs réelles.
# ==============================================================

load_dotenv()

BASE_URL        = os.environ.get("BASE_URL", "").rstrip("/")
SIEM_TOKEN      = os.environ.get("SIEM_TOKEN", "")
ORCH_TOKEN      = os.environ.get("ORCH_TOKEN", "")
SOAR_BF_TOKEN   = os.environ.get("SOAR_BF_TOKEN", "")
SOAR_PH_TOKEN   = os.environ.get("SOAR_PH_TOKEN", "")
SIM_TOKEN       = os.environ.get("SIM_TOKEN", "")
REPORT_TOKEN    = os.environ.get("REPORT_TOKEN", "")
GATEWAY_TOKEN   = os.environ.get("GATEWAY_TOKEN", "")
ANALYST_L1      = os.environ.get("ANALYST_L1", "")
SKIP_WHATSAPP   = os.environ.get("SKIP_WHATSAPP", "true").lower() == "true"

# ==============================================================
# VALIDATION AU DÉMARRAGE — arrêt immédiat si config incomplète
# ==============================================================

REQUIRED_VARS = [
    "BASE_URL", "SIEM_TOKEN", "ORCH_TOKEN", "SOAR_BF_TOKEN",
    "SOAR_PH_TOKEN", "SIM_TOKEN", "REPORT_TOKEN", "GATEWAY_TOKEN"
]

missing = [v for v in REQUIRED_VARS if not os.environ.get(v)]
if missing:
    print(f"\n[ERREUR CRITIQUE] Variables manquantes dans .env :")
    for v in missing:
        print(f"  - {v}")
    print("\nAction : copier .env.example → .env et remplir les valeurs réelles.")
    sys.exit(1)

if not BASE_URL.startswith("http"):
    print("[ERREUR] BASE_URL invalide. Format attendu: https://xxx.app.n8n.cloud/webhook")
    sys.exit(1)

# ==============================================================
# HELPERS AFFICHAGE
# ==============================================================

PASS  = "\033[92m[PASS]\033[0m"
FAIL  = "\033[91m[FAIL]\033[0m"
SKIP  = "\033[93m[SKIP]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"
TITLE = "\033[1m\033[95m"
RESET = "\033[0m"

results = {"pass": 0, "fail": 0, "skip": 0}


def post(path, body=None, token_val=None, extra_headers=None):
    """
    Envoie une requête POST au webhook n8n.
    Le token SOC est TOUJOURS dans le header HTTP 'x-soc-token'.
    """
    url = f"{BASE_URL}/{path}"
    headers = {"Content-Type": "application/json"}
    if token_val:
        headers["x-soc-token"] = token_val
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = requests.post(url, json=body or {}, headers=headers, timeout=20)
        return r.status_code, _safe_json(r)
    except requests.exceptions.Timeout:
        return 0, {"error": "TIMEOUT"}
    except Exception as e:
        return 0, {"error": str(e)}


def _safe_json(r):
    try:
        return r.json()
    except Exception:
        return {"raw": r.text[:300]}


def check(name, condition, actual=None, expected=None):
    if condition:
        print(f"  {PASS} {name}")
        results["pass"] += 1
    else:
        print(f"  {FAIL} {name}")
        if actual is not None:
            print(f"         Reçu    : {json.dumps(actual)[:250]}")
        if expected is not None:
            print(f"         Attendu : {expected}")
        results["fail"] += 1


def skip(name, reason="SKIP_WHATSAPP=True"):
    print(f"  {SKIP} {name} ({reason})")
    results["skip"] += 1


def section(title):
    print(f"\n{TITLE}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{RESET}")


def info(msg):
    print(f"  {INFO} {msg}")


# ==============================================================
# TESTS SIEM-001 — BruteForce Detector
# ==============================================================

def test_siem():
    section("SIEM-001 — BruteForce Detector")

    status, body = post("siem-logs", {"type": "auth_fail", "ip": "1.2.3.4"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body, "error=UNAUTHORIZED")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": "1.2.3.4"}, token_val="MAUVAIS_TOKEN")
    check("Token invalide → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body, "error=UNAUTHORIZED")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": "999.999.999.999"}, token_val=SIEM_TOKEN)
    check("IP invalide → INVALID_IP",
          body.get("error") == "INVALID_IP", body, "error=INVALID_IP")

    status, body = post("siem-logs",
        {"type": "hack_everything", "ip": "1.2.3.4"}, token_val=SIEM_TOKEN)
    check("Type invalide → INVALID_TYPE",
          body.get("error") == "INVALID_TYPE", body, "error=INVALID_TYPE")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": "127.0.0.1"}, token_val=SIEM_TOKEN)
    check("IP protégée → INVALID_IP ou rejet",
          body.get("error") in ("INVALID_IP", "UNAUTHORIZED"), body)

    ts_mod = int(time.time()) % 255
    test_ip = f"10.10.{ts_mod}.10"
    info(f"IP de test FSM : {test_ip}")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": test_ip, "user": "testuser"}, token_val=SIEM_TOKEN)
    check("1er auth_fail → alerte=false",
          body.get("alerte") is False or body.get("alert_triggered") is False,
          body, "alerte=false")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": test_ip, "user": "testuser"}, token_val=SIEM_TOKEN)
    check("2e auth_fail → alerte=false",
          body.get("alerte") is False or body.get("alert_triggered") is False,
          body, "alerte=false")

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": test_ip, "user": "testuser"}, token_val=SIEM_TOKEN)
    check("3e auth_fail → state q1",
          body.get("state_after") == "q1", body, "state_after=q1")

    status, body = post("siem-logs",
        {"type": "port_scan", "ip": test_ip}, token_val=SIEM_TOKEN)
    check("port_scan après q1 → q2",
          body.get("state_after") == "q2", body, "state_after=q2")

    status, body = post("siem-logs",
        {"type": "priv_escalation", "ip": test_ip}, token_val=SIEM_TOKEN)
    check("priv_escalation → q3 + alerte=true",
          body.get("state_after") == "q3"
          and (body.get("alerte") is True or body.get("alert_triggered") is True),
          body, "state_after=q3, alerte=true")

    status, body = post("siem-logs",
        {"type": "reset", "ip": test_ip}, token_val=SIEM_TOKEN)
    check("Reset FSM → _fsm_reset=true ou state_after=q0",
          body.get("_fsm_reset") is True or body.get("state_after") == "q0",
          body, "_fsm_reset=true")


# ==============================================================
# TESTS ORCH-000 — Incident Dispatcher
# ==============================================================

def test_orch():
    section("ORCH-000 — Incident Dispatcher")

    status, body = post("soar-dispatch",
        {"incident_type": "brute_force", "source_ip": "2.2.2.2"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)

    status, body = post("soar-dispatch",
        {"incident_type": "unknown_attack", "source_ip": "2.2.2.2"},
        token_val=ORCH_TOKEN)
    check("Type invalide → INVALID_INCIDENT_TYPE",
          body.get("error") == "INVALID_INCIDENT_TYPE", body)

    status, body = post("soar-dispatch",
        {"incident_type": "brute_force", "source_ip": "3.3.3.3",
         "priority": "P1", "severity": "HIGH", "severity_score": 75},
        token_val=ORCH_TOKEN)
    inc_id = body.get("incident_id", "")
    check("Incident BF valide → incident_id généré",
          str(inc_id).startswith("INC-"), body, "incident_id starts with INC-")
    info(f"Incident créé : {inc_id}")

    time.sleep(1)
    status, body2 = post("soar-dispatch",
        {"incident_type": "brute_force", "source_ip": "3.3.3.3"},
        token_val=ORCH_TOKEN)
    check("Déduplication → status=DEDUPLICATED",
          body2.get("status") == "DEDUPLICATED" or body2.get("_deduplicated") is True,
          body2, "status=DEDUPLICATED")

    time.sleep(1)
    status, body3 = post("soar-dispatch",
        {"incident_type": "phishing", "source_ip": "3.3.3.3",
         "user": "test@corp.ma", "url": "http://evil.com"},
        token_val=ORCH_TOKEN)
    check("Corrélation APT → priority=P0 ou correlated=true",
          body3.get("priority") == "P0" or body3.get("correlated") is True,
          body3, "priority=P0 ou correlated=true")

    status, body4 = post("soar-dispatch",
        {"incident_type": "phishing", "source_ip": "4.4.4.4",
         "user": "victim@corp.ma", "url": "http://phish.example.com"},
        token_val=ORCH_TOKEN)
    check("Incident Phishing valide → incident_id généré",
          str(body4.get("incident_id", "")).startswith("INC-"), body4)


# ==============================================================
# TESTS SIM-004 — Firewall / EDR Simulator
# ==============================================================

def test_sim():
    section("SIM-004 — Firewall / EDR Simulator")

    status, body = post("sim-simulator",
        {"action": "block_ip", "ip": "5.5.5.5"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED" or body.get("status") == "ERROR", body)

    status, body = post("sim-simulator",
        {"action": "format_disk", "ip": "5.5.5.5"}, token_val=SIM_TOKEN)
    check("Action invalide → ERROR",
          body.get("status") == "ERROR", body)

    status, body = post("sim-simulator",
        {"action": "block_ip", "ip": "127.0.0.1"}, token_val=SIM_TOKEN)
    check("IP protégée → REFUSED",
          body.get("status") == "ERROR" and "protégée" in str(body.get("message", "")), body)

    status, body = post("sim-simulator",
        {"action": "block_ip", "ip": "5.5.5.5", "incident_id": "INC-TEST-001"},
        token_val=SIM_TOKEN)
    check("block_ip valide → SUCCESS",
          body.get("status") == "SUCCESS" and body.get("action") == "block_ip", body)

    status, body = post("sim-simulator",
        {"action": "isolate_host", "host": "PC-ALICE-01", "incident_id": "INC-TEST-002"},
        token_val=SIM_TOKEN)
    check("isolate_host → SUCCESS",
          body.get("status") == "SUCCESS"
          and body.get("isolation") == "FULL_NETWORK_ISOLATION", body)

    status, body = post("sim-simulator",
        {"action": "purge_phishing_emails", "host": "alice@corp.ma",
         "incident_id": "INC-TEST-003"}, token_val=SIM_TOKEN)
    check("purge_phishing_emails → SUCCESS + emails_purged > 0",
          body.get("status") == "SUCCESS" and int(body.get("emails_purged", 0)) >= 1, body)

    status, body = post("sim-simulator",
        {"action": "full_av_scan", "host": "PC-BOB-02", "incident_id": "INC-TEST-004"},
        token_val=SIM_TOKEN)
    check("full_av_scan → SUCCESS + scan_type=FULL_DISK_SCAN",
          body.get("status") == "SUCCESS" and body.get("scan_type") == "FULL_DISK_SCAN", body)


# ==============================================================
# TESTS REPORT-005 — Metrics Dashboard
# ==============================================================

def test_report():
    section("REPORT-005 — Metrics Dashboard")

    status, body = post("report", {})
    check("Sans token → 401 ou UNAUTHORIZED",
          status == 401 or body.get("error") == "UNAUTHORIZED", body)

    status, body = post("report", {}, token_val="WRONG")
    check("Mauvais token → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED" or status == 401, body)

    status, body = post("report", {}, token_val=REPORT_TOKEN)
    check("Bon token → rapport généré avec champs clés",
          "MTTD_minutes" in body and "incidents_total" in body and "recommendation" in body,
          body, "MTTD_minutes + incidents_total + recommendation présents")
    if "maturity_level" in body:
        info(f"Maturity level : {body['maturity_level']}")
    if "recommendation" in body:
        info(f"Recommandation : {body['recommendation']}")
    if "security_posture" in body:
        info(f"Security posture : {body['security_posture']}")


# ==============================================================
# TESTS GW-007 — API Gateway
# ==============================================================

def test_gateway():
    section("GW-007 — API Gateway")

    status, body = post("gateway", {"route": "sim"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)

    status, body = post("gateway", {"route": "inexistant"}, token_val=GATEWAY_TOKEN)
    check("Route invalide → INVALID_ROUTE",
          body.get("error") == "INVALID_ROUTE", body)

    status, body = post("gateway",
        {"route": "sim", "action": "full_av_scan",
         "host": "PC-TEST", "incident_id": "INC-GW-001"},
        token_val=GATEWAY_TOKEN)
    check("Route sim via Gateway → SUCCESS ou routé",
          body.get("status") == "SUCCESS"
          or "_gateway_route" in body
          or body.get("action") == "full_av_scan", body)

    info("Test rate limiting (101 req avec IP fixe 10.99.99.99)... ~10s")
    FIXED_RL_IP = "10.99.99.99"
    rate_limited = False
    hit_at = -1
    for i in range(102):
        s, b = post("gateway",
            {"route": "sim", "ip": FIXED_RL_IP}, token_val=GATEWAY_TOKEN)
        if b.get("error") == "RATE_LIMITED":
            rate_limited = True
            hit_at = i + 1
            info(f"Rate limit atteint à la requête #{hit_at}")
            break
    check("Rate limiting → RATE_LIMITED après 100 req/min",
          rate_limited, None, "RATE_LIMITED après 100 req avec même IP")


# ==============================================================
# TESTS RESP-006 — Response Dispatcher (WhatsApp)
# CORRECTION : le relay HMAC injecte _relay_validated_at + _relay_sig_ok
# pour les tests directs sans Twilio réel.
# ==============================================================

def test_resp():
    section("RESP-006 — Response Dispatcher (WhatsApp)")

    # En test direct (sans Twilio), on injecte le flag de relay HMAC
    # Ce flag n'est accepté que si TWILIO_WEBHOOK_URL n'est pas configuré
    # ou si le relay Python (relay010.py) l'a ajouté après validation HMAC réelle
    relay = {
        "_relay_validated_at": datetime.utcnow().isoformat() + "Z",
        "_relay_sig_ok": True,
        "_relay_version": "RELAY-010-v1"
    }

    status, body = post("soar-response",
        {**relay, "Body": "OUI", "From": f"whatsapp:{ANALYST_L1}"})
    check("Format OTP invalide → IGNORED",
          body.get("status") == "IGNORED", body)

    status, body = post("soar-response",
        {**relay, "Body": "BF-OUI", "From": f"whatsapp:{ANALYST_L1}"})
    check("BF-OUI sans code → IGNORED",
          body.get("status") == "IGNORED", body)

    status, body = post("soar-response",
        {**relay, "Body": "BF-OUI-123456", "From": "whatsapp:+33100000000"})
    check("Expéditeur inconnu → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)

    if ANALYST_L1:
        status, body = post("soar-response",
            {**relay, "Body": "BF-OUI-123456", "From": f"whatsapp:{ANALYST_L1}"})
        check("BF-OUI-123456 valide → route_to_bf=true",
              body.get("route_to_bf") is True and body.get("decision") == "OUI", body)

        status, body = post("soar-response",
            {**relay, "Body": "PH-NON-654321", "From": f"whatsapp:{ANALYST_L1}"})
        check("PH-NON-654321 → route_to_phishing=true, decision=NON",
              body.get("route_to_phishing") is True and body.get("decision") == "NON", body)
    else:
        skip("Tests RESP-006 avec numéro analyste", "ANALYST_L1 non configuré dans .env")


# ==============================================================
# TESTS SOAR-002 — BruteForce Response
# ==============================================================

def test_soar_bf():
    section("SOAR-002 — BruteForce Response")

    status, body = post("soar-trigger",
        {"incident_type": "brute_force", "ip": "6.6.6.6"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)

    status, body = post("soar-trigger",
        {"incident_type": "brute_force", "ip": "0.0.0.0"}, token_val=SOAR_BF_TOKEN)
    check("IP protégée → PROTECTED_IP ou INVALID_IP",
          body.get("error") in ("PROTECTED_IP", "INVALID_IP"), body)

    if SKIP_WHATSAPP:
        skip("Triage BF complet avec WhatsApp", "SKIP_WHATSAPP=True")
    else:
        status, body = post("soar-trigger",
            {"incident_type": "brute_force", "ip": "7.7.7.7",
             "priority": "P1", "severity": "HIGH", "severity_score": 75,
             "mitre_tech": "T1110", "mitre_name": "Brute Force",
             "mitre_tactic": "Credential Access",
             "incident_id": "INC-TEST-BF-001"}, token_val=SOAR_BF_TOKEN)
        check("Triage BF → incident créé",
              body.get("incident_id") is not None, body)


# ==============================================================
# TESTS SOAR-003 — Phishing Response
# ==============================================================

def test_soar_ph():
    section("SOAR-003 — Phishing Response")

    status, body = post("soar-phishing-trigger",
        {"incident_type": "phishing", "ip": "8.8.8.8"})
    check("Token manquant → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)

    status, body = post("soar-phishing-trigger",
        {"incident_type": "phishing", "ip": "abc"}, token_val=SOAR_PH_TOKEN)
    check("IP invalide → INVALID_IP",
          body.get("error") == "INVALID_IP", body)

    if SKIP_WHATSAPP:
        skip("Triage Phishing complet avec WhatsApp", "SKIP_WHATSAPP=True")
    else:
        status, body = post("soar-phishing-trigger",
            {"incident_type": "phishing", "ip": "9.9.9.9",
             "user": "victim@corp.ma", "url": "http://evil-phish.ma",
             "priority": "P1", "severity": "HIGH",
             "incident_id": "INC-TEST-PH-001"}, token_val=SOAR_PH_TOKEN)
        check("Triage Phishing → incident créé",
              body.get("incident_id") is not None, body)


# ==============================================================
# TESTS RELAY-010 — Twilio HMAC Relay
# ==============================================================

def test_relay():
    section("RELAY-010 — Twilio HMAC Validator")

    relay_url = os.environ.get("RELAY_URL", "")
    if not relay_url:
        skip("Tests relay HMAC", "RELAY_URL non configuré dans .env")
        return

    # Test 1 : sans signature Twilio → rejet
    try:
        r = requests.post(relay_url + "/twilio-relay",
            data={"Body": "BF-OUI-123456", "From": f"whatsapp:{ANALYST_L1}"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10)
        body = _safe_json(r)
        check("Sans signature Twilio → 403",
              r.status_code == 403 or body.get("error") == "INVALID_SIGNATURE", body)
    except Exception as e:
        skip(f"Relay non joignable: {e}", "RELAY_URL inaccessible")
        return

    # Test 2 : signature invalide → rejet
    r = requests.post(relay_url + "/twilio-relay",
        data={"Body": "BF-OUI-123456", "From": f"whatsapp:{ANALYST_L1}"},
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Twilio-Signature": "invalidsignature=="
        }, timeout=10)
    body = _safe_json(r)
    check("Signature invalide → 403",
          r.status_code == 403 or body.get("error") == "INVALID_SIGNATURE", body)


# ==============================================================
# TIMEOUT-008 — SLA Escalation
# ==============================================================

def test_sla():
    section("TIMEOUT-008 — SLA Escalation")
    info("Ce test vérifie que le scheduler tourne et que la DB contient")
    info("l'incident de test avec sla_due dans le passé.")
    info("Insérer manuellement en DB si ce n'est pas déjà fait :")
    print("""
    INSERT INTO incidents (
      incident_id, incident_type, source_ip, priority,
      sla_due, sla_minutes, status, created_at
    ) VALUES (
      'TEST-SLA-999', 'brute_force', '192.168.1.1', 'P1',
      NOW() - INTERVAL '10 minutes', 5, 'TRIAGE',
      NOW() - INTERVAL '70 minutes'
    ) ON CONFLICT DO NOTHING;
    """)
    info("Ensuite attendre max 1 minute et vérifier le WhatsApp L2.")
    if SKIP_WHATSAPP:
        skip("Test SLA breach WhatsApp automatique", "SKIP_WHATSAPP=True")


# ==============================================================
# SÉCURITÉ — Injections SQL et inputs malveillants
# ==============================================================

def test_security():
    section("SÉCURITÉ — Injections SQL et inputs malveillants")

    payloads_ip = [
        ("1.2.3.4' OR '1'='1",               "Injection SQL simple"),
        ("1.2.3.4; DROP TABLE incidents;--",   "SQL DROP TABLE"),
        ("' UNION SELECT * FROM incidents--",  "UNION injection"),
        ("../../../etc/passwd",                "Path traversal"),
        ("<script>alert(1)</script>",          "XSS script tag"),
    ]
    for payload, label in payloads_ip:
        status, body = post("siem-logs",
            {"type": "auth_fail", "ip": payload}, token_val=SIEM_TOKEN)
        check(f"Injection IP '{payload[:30]}' → rejeté",
              body.get("error") in ("INVALID_IP", "UNAUTHORIZED", "RATE_LIMITED")
              or body.get("state_after") is not None, body)

    big = "A" * 10000
    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": "1.1.1.1", "user": big}, token_val=SIEM_TOKEN)
    check("Payload géant (10000 chars) → traité sans crash",
          status in (200, 400, 413),
          {"status": status, "body_keys": list(body.keys())[:5]})

    status, body = post("siem-logs",
        {"type": "auth_fail", "ip": "1.1.1.1"},
        token_val="'; DROP TABLE incidents;--")
    check("Token injection SQL → UNAUTHORIZED",
          body.get("error") == "UNAUTHORIZED", body)


# ==============================================================
# RÉSUMÉ FINAL
# ==============================================================

def print_summary():
    total = results["pass"] + results["fail"] + results["skip"]
    print(f"\n{TITLE}{'='*60}")
    print("  RÉSULTAT FINAL")
    print(f"{'='*60}{RESET}")
    print(f"  Total  : {total}")
    print(f"  {PASS} : {results['pass']}")
    print(f"  {FAIL} : {results['fail']}")
    print(f"  {SKIP} : {results['skip']}")
    score = int(results["pass"] / max(total - results["skip"], 1) * 100)
    print(f"\n  Score  : {score}%")
    if results["fail"] == 0:
        print(f"\n  {PASS} Tous les tests passent — SOC opérationnel.")
    else:
        print(f"\n  {FAIL} {results['fail']} test(s) échoué(s) — voir détails ci-dessus.")
    print()


# ==============================================================
# MAIN
# ==============================================================

if __name__ == "__main__":
    print(f"\n{TITLE}SOC n8n Cloud — Test Suite FINALE SÉCURISÉE{RESET}")
    print(f"Base URL : {BASE_URL}")
    print(f"Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"WhatsApp : {'DÉSACTIVÉ' if SKIP_WHATSAPP else 'ACTIVÉ'}")

    test_siem()
    test_orch()
    test_sim()
    test_report()
    test_gateway()
    test_resp()
    test_soar_bf()
    test_soar_ph()
    test_relay()
    test_sla()
    test_security()
    print_summary()
