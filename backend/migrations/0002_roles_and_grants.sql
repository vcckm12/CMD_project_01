-- Source of truth: docs/02_database_design.md §5 (DES-002 v1.1). NOLOGIN group roles only.
-- Login roles and passwords are provisioned by the deploy step (migrate.py), never here.

CREATE ROLE auth_service NOLOGIN;
CREATE ROLE shop_reader NOLOGIN;
CREATE ROLE shop_writer NOLOGIN;
CREATE ROLE rule_reader NOLOGIN;
CREATE ROLE rule_publisher NOLOGIN;
CREATE ROLE audit_ingest NOLOGIN;
CREATE ROLE audit_worker NOLOGIN;
CREATE ROLE audit_reader NOLOGIN;
CREATE ROLE maintenance_worker NOLOGIN;
CREATE ROLE retention_worker NOLOGIN;
REVOKE ALL ON SCHEMA commerce, threat_intel, audit FROM PUBLIC;
GRANT USAGE ON SCHEMA commerce TO auth_service, shop_reader, shop_writer, maintenance_worker, retention_worker;
GRANT SELECT, INSERT, UPDATE ON commerce.users, commerce.refresh_tokens, commerce.client_tokens TO auth_service;
GRANT SELECT ON commerce.users TO shop_reader, shop_writer;
GRANT SELECT ON commerce.products, commerce.orders, commerce.order_items, commerce.coupons,
  commerce.user_coupons, commerce.carts, commerce.cart_items, commerce.chat_sessions, commerce.actions
  TO shop_reader, shop_writer;
GRANT INSERT, UPDATE ON commerce.carts, commerce.chat_sessions, commerce.actions TO shop_writer;
GRANT INSERT, UPDATE, DELETE ON commerce.cart_items TO shop_writer;
GRANT USAGE ON SCHEMA threat_intel TO rule_reader, rule_publisher, audit_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA threat_intel TO rule_reader, rule_publisher, audit_worker;
GRANT INSERT, UPDATE ON threat_intel.rulesets TO rule_publisher;
GRANT INSERT, UPDATE, DELETE ON threat_intel.rules TO rule_publisher;
GRANT INSERT ON threat_intel.policy_publications TO rule_publisher;
GRANT USAGE ON SCHEMA audit TO audit_ingest, audit_worker, audit_reader, maintenance_worker, retention_worker;
GRANT INSERT ON audit.outbox TO audit_ingest;
GRANT SELECT, UPDATE ON audit.outbox TO audit_worker;
GRANT SELECT, INSERT ON audit.events, audit.rule_hits, audit.tool_executions TO audit_worker;
GRANT SELECT ON audit.events, audit.rule_hits, audit.tool_executions TO audit_reader;
GRANT SELECT, UPDATE ON commerce.actions, commerce.user_coupons TO maintenance_worker;
GRANT SELECT ON commerce.coupons TO maintenance_worker;
GRANT INSERT ON audit.outbox TO maintenance_worker;
GRANT SELECT, DELETE ON commerce.actions TO retention_worker;
GRANT SELECT, DELETE ON commerce.chat_sessions, commerce.refresh_tokens, commerce.client_tokens TO retention_worker;
GRANT SELECT, DELETE ON audit.outbox, audit.events, audit.rule_hits, audit.tool_executions TO retention_worker;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA threat_intel FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA commerce FROM PUBLIC;
