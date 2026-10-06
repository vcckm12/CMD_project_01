-- Ops dashboard reads (DES-005 §2.4): ingestion lag and ruleset labels without payloads or rule text.
GRANT SELECT (delivery_state, created_at) ON audit.outbox TO audit_reader;
GRANT USAGE ON SCHEMA threat_intel TO audit_reader;
GRANT SELECT (id, version_label) ON threat_intel.rulesets TO audit_reader;
