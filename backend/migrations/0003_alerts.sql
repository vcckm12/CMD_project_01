-- Ops alerts (D-26). Shown on the Streamlit dashboard; no external notification yet.
-- Holds no user text: only a keyed input fingerprint, fixed detail text and counters.

CREATE TABLE audit.alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind varchar(40) NOT NULL CHECK (kind IN ('judge_unavailable', 'suspicious_input_repeat')),
  severity varchar(16) NOT NULL CHECK (severity IN ('warning', 'critical')),
  fingerprint char(64) CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  detail varchar(300) NOT NULL,
  occurrences integer NOT NULL DEFAULT 1 CHECK (occurrences > 0),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  state varchar(16) NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged')),
  acknowledged_by uuid REFERENCES commerce.users(id),
  acknowledged_at timestamptz,
  CHECK ((state = 'open' AND acknowledged_by IS NULL AND acknowledged_at IS NULL) OR
         (state = 'acknowledged' AND acknowledged_by IS NOT NULL AND acknowledged_at IS NOT NULL))
);
-- At most one open alert per kind and fingerprint; repeats increase `occurrences`.
CREATE UNIQUE INDEX alerts_one_open_idx ON audit.alerts (kind, (coalesce(fingerprint, ''))) WHERE state = 'open';
CREATE INDEX alerts_state_idx ON audit.alerts (state, last_seen_at DESC);

CREATE ROLE alert_writer NOLOGIN;
CREATE ROLE alert_manager NOLOGIN;
GRANT USAGE ON SCHEMA audit TO alert_writer, alert_manager;
GRANT SELECT, INSERT ON audit.alerts TO alert_writer;
GRANT UPDATE (occurrences, last_seen_at, severity) ON audit.alerts TO alert_writer;
GRANT SELECT ON audit.alerts TO audit_reader, alert_manager;
GRANT UPDATE (state, acknowledged_by, acknowledged_at) ON audit.alerts TO alert_manager;
GRANT SELECT, DELETE ON audit.alerts TO retention_worker;
