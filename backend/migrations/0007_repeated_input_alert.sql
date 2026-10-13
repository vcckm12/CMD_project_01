-- D-47: alert when the same question arrives repeatedly (attack probing, or a customer stuck behind a false
-- positive). Still no user text: the keyed fingerprint, the last event id and the blocking rule ids only.
ALTER TABLE audit.alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE audit.alerts ADD CONSTRAINT alerts_kind_check
  CHECK (kind IN ('judge_unavailable', 'suspicious_input_repeat', 'outbox_dead', 'repeated_input'));
ALTER TABLE audit.alerts
  ADD COLUMN last_event_id uuid,
  ADD COLUMN rule_ids varchar(300) CHECK (rule_ids ~ '^[A-Z0-9_, ]*$');
GRANT UPDATE (detail, last_event_id, rule_ids) ON audit.alerts TO alert_writer;
