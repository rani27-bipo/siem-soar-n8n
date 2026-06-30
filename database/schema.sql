-- ============================================================
-- SCHÉMA SUPABASE SOC n8n Automatisé
-- ============================================================
-- Tables :
--   incidents          — Table principale SOC
--   fsm_sessions       — États FSM SIEM-001 par IP
--   otp_challenges     — Codes OTP WhatsApp SOAR-002/003
--   dedup_cache        — Déduplication incidents ORCH-000
--   correlation_cache  — Corrélation APT persistante (NEW)
--   workflow_logs      — Logs structurés persistants (NEW)
--   threat_intel_cache — Cache AbuseIPDB/VT (NEW)
-- Vue :
--   vw_soc_dashboard   — Métriques temps réel REPORT-005
-- ============================================================

-- ── ÉTAPE 0 : NETTOYAGE COMPLET ─────────────────────────────

-- Désactiver RLS pour DROP propre
ALTER TABLE IF EXISTS incidents           DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS fsm_sessions        DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS otp_challenges      DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS dedup_cache         DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS correlation_cache   DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS workflow_logs       DISABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS threat_intel_cache  DISABLE ROW LEVEL SECURITY;

-- Vues
DROP VIEW IF EXISTS vw_soc_dashboard CASCADE;

-- Politiques
DO $$ DECLARE
  r RECORD;
BEGIN
  FOR r IN SELECT schemaname, tablename, policyname
           FROM pg_policies
           WHERE schemaname = 'public'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
                   r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- Fonctions
DROP FUNCTION IF EXISTS purge_old_fsm_sessions();
DROP FUNCTION IF EXISTS purge_expired_otp();
DROP FUNCTION IF EXISTS purge_expired_dedup();
DROP FUNCTION IF EXISTS purge_correlation_cache();
DROP FUNCTION IF EXISTS purge_workflow_logs();
DROP FUNCTION IF EXISTS purge_threat_intel();
DROP FUNCTION IF EXISTS purge_all_expired();
DROP FUNCTION IF EXISTS update_updated_at_column();

-- ── ÉTAPE 1 : TABLE INCIDENTS ────────────────────────────────

CREATE TABLE IF NOT EXISTS incidents (

  -- Identifiants
  id              SERIAL        PRIMARY KEY,
  incident_id     VARCHAR(50)   NOT NULL UNIQUE,

  -- Classification
  incident_type   VARCHAR(30)   NOT NULL
    CHECK (incident_type IN (
      'brute_force','phishing','data_exfil',
      'port_scan','priv_escalation','unknown'
    )),
  source_ip       VARCHAR(45)   NOT NULL,
  username        VARCHAR(100)  DEFAULT 'unknown',
  session_id      VARCHAR(100),
  url             VARCHAR(1000),

  -- Statut & priorité
  status          VARCHAR(30)   NOT NULL DEFAULT 'TRIAGE'
    CHECK (status IN (
      'TRIAGE','CONTAINED','ESCALATED','CLOSED','DEDUPLICATED'
    )),
  priority        VARCHAR(5)    NOT NULL DEFAULT 'P1'
    CHECK (priority IN ('P0','P1','P2','P3','P4')),
  severity        VARCHAR(20)   NOT NULL DEFAULT 'HIGH'
    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
  severity_score  SMALLINT      DEFAULT 75
    CHECK (severity_score BETWEEN 0 AND 100),
  risk_score      SMALLINT      DEFAULT 0
    CHECK (risk_score BETWEEN 0 AND 100),

  -- MITRE ATT&CK
  mitre_tech      VARCHAR(20),
  mitre_name      VARCHAR(100),
  mitre_tactic    VARCHAR(100),

  -- SLA
  sla_minutes     SMALLINT      DEFAULT 60
    CHECK (sla_minutes > 0),
  sla_due         TIMESTAMPTZ,
  sla_breached    BOOLEAN       DEFAULT FALSE,
  last_escalation_sent_at TIMESTAMPTZ,

  -- FSM
  etat_siem       VARCHAR(5)    DEFAULT 'q0'
    CHECK (etat_siem IN ('q0','q1','q2','q3','q4')),
  etat_soar       VARCHAR(30)   DEFAULT 'q1_Triage'
    CHECK (etat_soar IN (
      'q1_Triage','q2_Enrichissement','q2_Enrichissement_Partiel',
      'q3_Attente_Analyste','q4_Containment',
      'q5_Escalation','q6_Closed','q6_Cloture'
    )),

  -- Corrélation APT
  correlated      BOOLEAN       DEFAULT FALSE,
  correl_types    VARCHAR(200),

  -- Enrichissement AbuseIPDB
  abuse_score     SMALLINT      DEFAULT 0
    CHECK (abuse_score BETWEEN 0 AND 100),
  abuse_country   VARCHAR(100),
  abuse_isp       VARCHAR(200),
  abuse_verdict   VARCHAR(20)   DEFAULT 'UNKNOWN'
    CHECK (abuse_verdict IN ('CLEAN','SUSPICIOUS','MALICIOUS','UNKNOWN','UNAVAILABLE')),

  -- Enrichissement VirusTotal
  vt_verdict      VARCHAR(20)   DEFAULT 'UNKNOWN'
    CHECK (vt_verdict IN ('CLEAN','MALICIOUS','SUSPICIOUS','UNKNOWN','UNAVAILABLE')),
  vt_score        SMALLINT      DEFAULT 0
    CHECK (vt_score BETWEEN 0 AND 100),
  vt_country      VARCHAR(100)  DEFAULT 'Unknown',
  vt_asn_owner    VARCHAR(200)  DEFAULT 'Unknown',

  -- Décision analyste
  decided_by      VARCHAR(100),
  decided_at      TIMESTAMPTZ,
  decision        VARCHAR(10)
    CHECK (decision IS NULL OR decision IN ('OUI','NON')),

  -- Containment
  firewall_rule   VARCHAR(100),

  -- Timestamps MTTD/MTTR
  first_alert_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ   DEFAULT NOW(),
  closed_at       TIMESTAMPTZ,

  -- Audit trail (limité à 50000 chars)
  audit_trail     VARCHAR(50000)
);

COMMENT ON TABLE incidents IS 'Table principale SOC — tous les incidents de sécurité';
COMMENT ON COLUMN incidents.audit_trail IS 'Log chronologique des événements — max 50000 chars';

-- ── ÉTAPE 2 : TABLE FSM_SESSIONS ─────────────────────────────

CREATE TABLE IF NOT EXISTS fsm_sessions (
  ip          TEXT        PRIMARY KEY
    CHECK (length(ip) <= 45),
  state       TEXT        NOT NULL DEFAULT 'q0'
    CHECK (state IN ('q0','q1','q2','q3','q4')),
  counter     INTEGER     NOT NULL DEFAULT 0
    CHECK (counter >= 0),
  session_id  TEXT        NOT NULL DEFAULT 'SESS-INIT',
  alert_sent  BOOLEAN     NOT NULL DEFAULT FALSE,
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE fsm_sessions IS 'États FSM par IP — détection brute force SIEM-001';

-- ── ÉTAPE 3 : TABLE OTP_CHALLENGES ───────────────────────────

CREATE TABLE IF NOT EXISTS otp_challenges (
  incident_id  TEXT        PRIMARY KEY
    CHECK (length(incident_id) <= 50),
  otp_code     TEXT        NOT NULL
    CHECK (otp_code ~ '^\d{6}$'),        -- exactement 6 chiffres
  phone        TEXT        NOT NULL
    CHECK (length(phone) <= 20),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
  used         BOOLEAN     NOT NULL DEFAULT FALSE,
  -- Contrainte : expires_at > created_at
  CONSTRAINT otp_expiry_valid CHECK (expires_at > created_at)
);

COMMENT ON TABLE otp_challenges IS 'Codes OTP WhatsApp — valides 5 min — SOAR-002/003';

-- ── ÉTAPE 4 : TABLE DEDUP_CACHE ──────────────────────────────

CREATE TABLE IF NOT EXISTS dedup_cache (
  dedup_key   TEXT        PRIMARY KEY
    CHECK (length(dedup_key) <= 200),
  incident_id TEXT        NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
  CONSTRAINT dedup_expiry_valid CHECK (expires_at > created_at)
);

COMMENT ON TABLE dedup_cache IS 'Cache déduplication incidents — fenêtre 15min — ORCH-000';

-- ── ÉTAPE 5 : TABLE CORRELATION_CACHE (NOUVELLE) ─────────────
-- Remplace la corrélation APT en StaticData n8n (volatile)
-- par une corrélation persistante en base de données.

CREATE TABLE IF NOT EXISTS correlation_cache (
  cache_key     TEXT        PRIMARY KEY
    CHECK (length(cache_key) <= 200),
  incident_id   TEXT        NOT NULL,
  source_ip     TEXT        NOT NULL
    CHECK (length(source_ip) <= 45),
  incident_type TEXT        NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour'),
  CONSTRAINT correl_expiry_valid CHECK (expires_at > created_at)
);

COMMENT ON TABLE correlation_cache IS 'Corrélation APT persistante par IP — fenêtre 1h — ORCH-000';

-- ── ÉTAPE 6 : TABLE WORKFLOW_LOGS (NOUVELLE) ─────────────────
-- Logs structurés persistants de tous les workflows n8n.
-- Remplace les console.log() qui disparaissent au restart.

CREATE TABLE IF NOT EXISTS workflow_logs (
  id           BIGSERIAL     PRIMARY KEY,
  workflow     VARCHAR(20)   NOT NULL,
  level        VARCHAR(10)   NOT NULL DEFAULT 'INFO'
    CHECK (level IN ('DEBUG','INFO','WARN','ERROR','SECURITY')),
  incident_id  VARCHAR(50),
  source_ip    VARCHAR(45),
  message      VARCHAR(500)  NOT NULL,
  context      JSONB,
  created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE workflow_logs IS 'Logs structurés persistants de tous les workflows n8n';

-- Partitionner par semaine en production (optionnel)
-- Pour ce projet : rétention 30 jours via purge MAINT-009

-- ── ÉTAPE 7 : TABLE THREAT_INTEL_CACHE (NOUVELLE) ────────────
-- Cache de threat intelligence pour éviter les appels API répétés
-- vers AbuseIPDB et VirusTotal pour les mêmes IPs.

CREATE TABLE IF NOT EXISTS threat_intel_cache (
  ip              TEXT        PRIMARY KEY
    CHECK (length(ip) <= 45),
  -- AbuseIPDB
  abuse_score     SMALLINT    DEFAULT 0
    CHECK (abuse_score BETWEEN 0 AND 100),
  abuse_country   TEXT        DEFAULT 'Unknown',
  abuse_isp       TEXT        DEFAULT 'Unknown',
  abuse_verdict   TEXT        DEFAULT 'UNKNOWN'
    CHECK (abuse_verdict IN ('CLEAN','SUSPICIOUS','MALICIOUS','UNKNOWN')),
  -- VirusTotal
  vt_score        SMALLINT    DEFAULT 0
    CHECK (vt_score BETWEEN 0 AND 100),
  vt_country      TEXT        DEFAULT 'Unknown',
  vt_asn_owner    TEXT        DEFAULT 'Unknown',
  vt_verdict      TEXT        DEFAULT 'UNKNOWN'
    CHECK (vt_verdict IN ('CLEAN','SUSPICIOUS','MALICIOUS','UNKNOWN')),
  -- Méta
  fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '6 hours'),
  query_count     INTEGER     DEFAULT 1,
  CONSTRAINT ti_expiry_valid CHECK (expires_at > fetched_at)
);

COMMENT ON TABLE threat_intel_cache IS 'Cache TI — AbuseIPDB + VT — expire 6h — évite les appels API répétés';

-- ── ÉTAPE 8 : INDEX DE PERFORMANCE ───────────────────────────

-- incidents
CREATE INDEX IF NOT EXISTS idx_incidents_status
  ON incidents(status) WHERE status != 'CLOSED';

CREATE INDEX IF NOT EXISTS idx_incidents_priority
  ON incidents(priority, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_sla_due
  ON incidents(sla_due) WHERE status NOT IN ('CLOSED','ESCALATED','DEDUPLICATED');

CREATE INDEX IF NOT EXISTS idx_incidents_created
  ON incidents(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
  ON incidents(source_ip, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_sla_breach
  ON incidents(last_escalation_sent_at)
  WHERE sla_breached = TRUE AND status NOT IN ('CLOSED','ESCALATED','DEDUPLICATED');

-- fsm_sessions
CREATE INDEX IF NOT EXISTS idx_fsm_last_seen
  ON fsm_sessions(last_seen);

-- otp_challenges — index composite pour requête de validation
CREATE INDEX IF NOT EXISTS idx_otp_lookup
  ON otp_challenges(incident_id, expires_at)
  WHERE used = FALSE;

CREATE INDEX IF NOT EXISTS idx_otp_purge
  ON otp_challenges(expires_at)
  WHERE used = FALSE;

-- dedup_cache
CREATE INDEX IF NOT EXISTS idx_dedup_expires
  ON dedup_cache(expires_at);

-- correlation_cache — recherche par IP pour corrélation APT
CREATE INDEX IF NOT EXISTS idx_correl_ip_expires
  ON correlation_cache(source_ip, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_correl_expires
  ON correlation_cache(expires_at);

-- workflow_logs
CREATE INDEX IF NOT EXISTS idx_wf_logs_incident
  ON workflow_logs(incident_id) WHERE incident_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_wf_logs_level_ts
  ON workflow_logs(level, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_wf_logs_workflow_ts
  ON workflow_logs(workflow, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_wf_logs_security
  ON workflow_logs(created_at DESC)
  WHERE level = 'SECURITY';

-- threat_intel_cache
CREATE INDEX IF NOT EXISTS idx_ti_expires
  ON threat_intel_cache(expires_at);

-- ── ÉTAPE 9 : TRIGGER UPDATED_AT ─────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS set_updated_at ON incidents;
CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON incidents
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- ── ÉTAPE 10 : FONCTIONS DE PURGE ────────────────────────────

-- Purge FSM sessions inactives depuis 2h (plus conservateur que 1h)
CREATE OR REPLACE FUNCTION purge_old_fsm_sessions()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM fsm_sessions
    WHERE last_seen < NOW() - INTERVAL '2 hours'
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge OTP expirés
CREATE OR REPLACE FUNCTION purge_expired_otp()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM otp_challenges
    WHERE expires_at < NOW()
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge dedup cache expiré
CREATE OR REPLACE FUNCTION purge_expired_dedup()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM dedup_cache
    WHERE expires_at < NOW()
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge corrélation cache expiré
CREATE OR REPLACE FUNCTION purge_correlation_cache()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM correlation_cache
    WHERE expires_at < NOW()
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge workflow_logs > 30 jours
CREATE OR REPLACE FUNCTION purge_workflow_logs()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM workflow_logs
    WHERE created_at < NOW() - INTERVAL '30 days'
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge threat_intel_cache expiré
CREATE OR REPLACE FUNCTION purge_threat_intel()
RETURNS INTEGER LANGUAGE sql AS $$
  WITH deleted AS (
    DELETE FROM threat_intel_cache
    WHERE expires_at < NOW()
    RETURNING 1
  )
  SELECT COUNT(*)::INTEGER FROM deleted;
$$;

-- Purge globale — appelée par MAINT-009 toutes les heures
CREATE OR REPLACE FUNCTION purge_all_expired()
RETURNS TABLE(
  otp_purged     INTEGER,
  dedup_purged   INTEGER,
  correl_purged  INTEGER,
  fsm_purged     INTEGER,
  ti_purged      INTEGER,
  logs_purged    INTEGER
) LANGUAGE sql AS $$
  SELECT
    purge_expired_otp()       AS otp_purged,
    purge_expired_dedup()     AS dedup_purged,
    purge_correlation_cache() AS correl_purged,
    purge_old_fsm_sessions()  AS fsm_purged,
    purge_threat_intel()      AS ti_purged,
    purge_workflow_logs()     AS logs_purged;
$$;

-- ── ÉTAPE 11 : VUE DASHBOARD (REPORT-005) ────────────────────
-- Calcul dynamique des métriques SOC sur les 24 dernières heures

CREATE OR REPLACE VIEW vw_soc_dashboard AS
WITH base AS (
  SELECT * FROM incidents
  WHERE created_at >= NOW() - INTERVAL '24 hours'
),
metrics AS (
  SELECT
    -- Comptages
    COUNT(*)                                                    AS total_incidents,
    COUNT(*) FILTER (WHERE status NOT IN ('CLOSED','ESCALATED','DEDUPLICATED'))
                                                                AS open_incidents,
    COUNT(*) FILTER (WHERE status = 'CLOSED')                   AS closed_incidents,

    -- Par priorité
    COUNT(*) FILTER (WHERE priority = 'P0')                     AS p0_count,
    COUNT(*) FILTER (WHERE priority = 'P1')                     AS p1_count,
    COUNT(*) FILTER (WHERE priority = 'P2')                     AS p2_count,

    -- Automatisation
    COUNT(*) FILTER (WHERE decided_by LIKE 'SOC_AUTO%' OR decided_by IS NULL)
                                                                AS auto_resolved,
    COUNT(*) FILTER (WHERE decided_by NOT LIKE 'SOC_AUTO%' AND decided_by IS NOT NULL)
                                                                AS human_escalated,

    -- SLA
    COUNT(*) FILTER (WHERE sla_breached = TRUE)                 AS sla_breached_count,

    -- MTTD : first_alert_at − created_at (en minutes)
    ROUND(
      AVG(
        EXTRACT(EPOCH FROM (first_alert_at - created_at)) / 60.0
      ) FILTER (WHERE first_alert_at IS NOT NULL AND first_alert_at > created_at)
      ::NUMERIC, 2
    )                                                           AS avg_mttd_minutes,

    -- MTTR : closed_at − created_at (en minutes)
    ROUND(
      AVG(
        EXTRACT(EPOCH FROM (closed_at - created_at)) / 60.0
      ) FILTER (WHERE closed_at IS NOT NULL AND closed_at > created_at)
      ::NUMERIC, 2
    )                                                           AS avg_mttr_minutes,

    -- Top sources
    MODE() WITHIN GROUP (ORDER BY source_ip)      AS top_source_ip,
    MODE() WITHIN GROUP (ORDER BY incident_type)  AS top_attack_type,
    MODE() WITHIN GROUP (ORDER BY mitre_tech)     AS top_mitre_tech

  FROM base
)
SELECT
  m.*,
  -- Colonnes calculées supplémentaires pour REPORT-005
  CASE
    WHEN m.total_incidents = 0 THEN 100
    ELSE ROUND(
      ((m.total_incidents - m.sla_breached_count)::NUMERIC / m.total_incidents) * 100, 1
    )
  END                                                           AS sla_compliance_pct,

  CASE
    WHEN m.total_incidents = 0 THEN 0
    ELSE ROUND(
      (m.auto_resolved::NUMERIC / m.total_incidents) * 100, 1
    )
  END                                                           AS automation_rate_pct,

  -- Niveau de maturité basé sur le MTTR
  CASE
    WHEN m.avg_mttr_minutes IS NULL THEN 'INDÉTERMINÉ'
    WHEN m.avg_mttr_minutes < 15    THEN 'ELITE (< 15 min MTTR)'
    WHEN m.avg_mttr_minutes < 30    THEN 'MATURE (< 30 min MTTR)'
    WHEN m.avg_mttr_minutes < 60    THEN 'EN PROGRESSION (< 60 min MTTR)'
    ELSE                                 'INITIAL (> 60 min MTTR)'
  END                                                           AS maturity_level,

  -- Security posture globale
  CASE
    WHEN m.p0_count > 0                     THEN 'RED'
    WHEN (
      (m.total_incidents > 0 AND
       ((m.total_incidents - m.sla_breached_count)::NUMERIC / m.total_incidents) < 0.80)
      OR (m.avg_mttr_minutes IS NOT NULL AND m.avg_mttr_minutes > 60)
      OR m.open_incidents > 10
      OR m.p1_count > 3
    )                                       THEN 'AMBER'
    ELSE                                         'GREEN'
  END                                                           AS security_posture,

  NOW()                                                         AS computed_at

FROM metrics m;

COMMENT ON VIEW vw_soc_dashboard IS
  'Métriques SOC temps réel — 24h — MTTD, MTTR, SLA, posture — REPORT-005';

-- ── ÉTAPE 12 : ROW LEVEL SECURITY ────────────────────────────

ALTER TABLE incidents           ENABLE ROW LEVEL SECURITY;
ALTER TABLE fsm_sessions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE otp_challenges      ENABLE ROW LEVEL SECURITY;
ALTER TABLE dedup_cache         ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_cache   ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_logs       ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_cache  ENABLE ROW LEVEL SECURITY;

-- Seul service_role (clé n8n) peut tout faire
CREATE POLICY "allow_service_role" ON incidents
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON fsm_sessions
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON otp_challenges
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON dedup_cache
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON correlation_cache
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON workflow_logs
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "allow_service_role" ON threat_intel_cache
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── ÉTAPE 13 : VARIABLE N8N — ajout à la liste ───────────────
-- Ajouter dans n8n Settings → Variables :
--
-- SUPABASE_OTP_URL  → https://PROJET.supabase.co/functions/v1/generate-otp
-- OTP_EDGE_TOKEN    → générer avec : python3 -c "import secrets; print(secrets.token_hex(24))"
-- RELAY_SECRET      → générer avec : python3 -c "import secrets; print(secrets.token_hex(32))"
-- WEBHOOK_SOAR_RESP006 → URL complète du webhook RESP-006
-- TWILIO_WEBHOOK_URL   → URL du relay RELAY-010 (pour activer mode PROD)
--
-- Variables existantes à conserver :
-- SIEM_TOKEN, ORCH_TOKEN, SOAR_BF_TOKEN, SOAR_PH_TOKEN
-- SIM_TOKEN, REPORT_TOKEN, GATEWAY_TOKEN
-- ANALYST_L1_PHONE, ANALYST_L2_PHONE
-- WEBHOOK_BASE, WEBHOOK_SOAR_BF, WEBHOOK_SOAR_PH
-- TWILIO_WEBHOOK_URL (mettre l'URL de RELAY-010 quand déployé)

-- ── ÉTAPE 14 : DONNÉES DE TEST (décommenter pour tester) ─────

/*
INSERT INTO incidents (
  incident_id, incident_type, source_ip, username,
  status, priority, severity, severity_score, risk_score,
  mitre_tech, mitre_name, mitre_tactic,
  sla_minutes, sla_due, sla_breached,
  etat_siem, etat_soar,
  first_alert_at, created_at, closed_at,
  decided_by, decided_at, decision,
  abuse_score, abuse_verdict, vt_verdict, vt_score,
  audit_trail
) VALUES
  (
    'INC-DEMO-001','brute_force','185.220.101.45','admin',
    'CLOSED','P1','HIGH',75,72,
    'T1110.001','Password Guessing','Credential Access',
    60, NOW() + INTERVAL '48 minutes', FALSE,
    'q3','q6_Closed',
    NOW() - INTERVAL '8 minutes', NOW() - INTERVAL '12 minutes', NOW() - INTERVAL '2 minutes',
    'SOC_L1_Analyst', NOW() - INTERVAL '3 minutes','OUI',
    87,'MALICIOUS','MALICIOUS',88,
    'Incident créé | Enrichissement VT+AbuseIPDB | Décision analyste OUI | IP bloquée PaloAlto'
  ),
  (
    'INC-DEMO-002','phishing','91.108.56.77','alice@corp.ma',
    'TRIAGE','P2','MEDIUM',50,45,
    'T1566.002','Spearphishing Link','Initial Access',
    240, NOW() + INTERVAL '200 minutes', FALSE,
    'q2','q3_Attente_Analyste',
    NOW() - INTERVAL '3 minutes', NOW() - INTERVAL '5 minutes', NULL,
    NULL, NULL, NULL,
    23,'CLEAN','SUSPICIOUS',22,
    'Incident phishing créé | En attente analyste'
  ),
  (
    'INC-DEMO-003','brute_force','192.168.1.200','root',
    'TRIAGE','P0','CRITICAL',100,98,
    'T1110.004','Credential Stuffing','Credential Access',
    15, NOW() - INTERVAL '10 minutes', TRUE,
    'q4','q3_Attente_Analyste',
    NOW() - INTERVAL '18 minutes', NOW() - INTERVAL '20 minutes', NULL,
    NULL, NULL, NULL,
    95,'MALICIOUS','MALICIOUS',97,
    'Incident P0 — SLA BREACHED — Escalade L2 envoyée'
  )
ON CONFLICT (incident_id) DO NOTHING;
*/

-- ── ÉTAPE 15 : VÉRIFICATION FINALE ───────────────────────────

-- Tables créées
SELECT
  t.table_name,
  COUNT(c.column_name) AS nb_colonnes,
  obj_description((t.table_schema||'.'||t.table_name)::regclass, 'pg_class') AS commentaire
FROM information_schema.tables t
JOIN information_schema.columns c USING (table_schema, table_name)
WHERE t.table_schema = 'public'
  AND t.table_type = 'BASE TABLE'
GROUP BY t.table_name, t.table_schema
ORDER BY t.table_name;

-- Vérifier la vue
SELECT * FROM vw_soc_dashboard;

-- Vérifier les index
SELECT
  tablename,
  indexname,
  LEFT(indexdef, 100) AS indexdef_short
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

-- Vérifier RLS
SELECT tablename, policyname, roles, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename;

-- ── RÉSUMÉ DES TABLES ────────────────────────────────────────
-- incidents          → Table principale — tous les incidents SOC
-- fsm_sessions       → États FSM par IP — SIEM-001
-- otp_challenges     → Codes OTP WhatsApp — SOAR-002 & SOAR-003
-- dedup_cache        → Cache déduplication 15min — ORCH-000
-- correlation_cache  → Corrélation APT persistante 1h — ORCH-000 (NEW)
-- workflow_logs      → Logs structurés 30 jours — tous workflows (NEW)
-- threat_intel_cache → Cache TI AbuseIPDB+VT 6h — SOAR-002/003 (NEW)
--
-- VUE : vw_soc_dashboard — métriques temps réel — REPORT-005
--   Inclut : MTTD, MTTR, SLA, automation_rate, maturity, posture
--
-- FONCTIONS DE PURGE (appelées par MAINT-009 toutes les heures) :
--   SELECT * FROM purge_all_expired();
-- ============================================================
