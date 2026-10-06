-- Audit worker and scheduler support (DES-002 §6, DES-007 §5).

-- A dead outbox event is an immediate critical alert on the ops dashboard.
ALTER TABLE audit.alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE audit.alerts ADD CONSTRAINT alerts_kind_check
  CHECK (kind IN ('judge_unavailable', 'suspicious_input_repeat', 'outbox_dead'));

-- Readiness reads the backlog size and age through the request pools without seeing payloads.
GRANT SELECT (delivery_state, created_at) ON audit.outbox TO audit_ingest;

-- Retention also removes acknowledged alerts after the audit period.
CREATE INDEX outbox_delivered_idx ON audit.outbox (delivered_at) WHERE delivery_state = 'delivered';
CREATE INDEX actions_resolved_idx ON commerce.actions (resolved_at) WHERE state <> 'pending';
