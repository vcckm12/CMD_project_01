-- Source of truth: docs/02_database_design.md §4 (DES-002 v1.1). Keep both in sync.
-- Applied by backend/app/db/migrate.py inside a single transaction.

CREATE SCHEMA commerce;
CREATE SCHEMA threat_intel;
CREATE SCHEMA audit;

CREATE TABLE commerce.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  login_email varchar(254) NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role varchar(16) NOT NULL DEFAULT 'customer'
    CHECK (role IN ('customer','operator','admin')),
  token_version integer NOT NULL DEFAULT 0 CHECK (token_version >= 0),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (login_email = lower(login_email))
);
CREATE TABLE commerce.refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  family_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at)
);
CREATE INDEX refresh_tokens_family_idx ON commerce.refresh_tokens(user_id, family_id);
CREATE TABLE commerce.client_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  name varchar(80) NOT NULL,
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0 AND
    scopes <@ ARRAY['chat:write','models:read','tools:read','shop:read','actions:propose']::text[]),
  token_version integer NOT NULL CHECK (token_version >= 0),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at)
);
CREATE INDEX client_tokens_user_idx ON commerce.client_tokens(user_id, created_at DESC);
CREATE TABLE commerce.chat_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  source varchar(16) NOT NULL CHECK (source IN ('web','anythingllm','streamlit')),
  context_redacted jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(context_redacted)='array'),
  risk_signals jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(risk_signals)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_activity_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, user_id)
);
CREATE INDEX chat_sessions_owner_idx ON commerce.chat_sessions(user_id, last_activity_at DESC);
CREATE TABLE commerce.products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sku varchar(64) NOT NULL UNIQUE,
  name varchar(200) NOT NULL,
  description varchar(2000) NOT NULL DEFAULT '',
  price_krw bigint NOT NULL CHECK (price_krw >= 0),
  stock_count integer NOT NULL DEFAULT 0 CHECK (stock_count >= 0),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX products_active_idx ON commerce.products(is_active, name);
CREATE TABLE commerce.orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  external_ref varchar(128) NOT NULL UNIQUE,
  status varchar(16) NOT NULL CHECK (status IN ('confirmed','shipped','delivered','cancelled')),
  total_krw bigint NOT NULL CHECK (total_krw >= 0),
  placed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX orders_owner_idx ON commerce.orders(user_id, placed_at DESC, id);
CREATE TABLE commerce.order_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES commerce.orders(id),
  product_id uuid NOT NULL REFERENCES commerce.products(id),
  product_name varchar(200) NOT NULL,
  unit_price_krw bigint NOT NULL CHECK (unit_price_krw >= 0),
  quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  UNIQUE (order_id, product_id)
);
CREATE TABLE commerce.coupons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code varchar(40) NOT NULL UNIQUE,
  discount_krw bigint NOT NULL CHECK (discount_krw > 0),
  min_subtotal_krw bigint NOT NULL DEFAULT 0 CHECK (min_subtotal_krw >= 0),
  expires_at timestamptz NOT NULL,
  is_active boolean NOT NULL DEFAULT true
);
CREATE TABLE commerce.user_coupons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  coupon_id uuid NOT NULL REFERENCES commerce.coupons(id),
  state varchar(16) NOT NULL DEFAULT 'available' CHECK (state IN ('available','used','expired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, coupon_id),
  UNIQUE (id, user_id)
);
CREATE TABLE commerce.carts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES commerce.users(id),
  version integer NOT NULL DEFAULT 0 CHECK (version >= 0),
  applied_coupon_id uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, user_id),
  FOREIGN KEY (applied_coupon_id, user_id) REFERENCES commerce.user_coupons(id, user_id)
);
CREATE TABLE commerce.cart_items (
  cart_id uuid NOT NULL REFERENCES commerce.carts(id) ON DELETE CASCADE,
  product_id uuid NOT NULL REFERENCES commerce.products(id),
  quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  PRIMARY KEY (cart_id, product_id)
);
CREATE TABLE threat_intel.rulesets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version_label varchar(64) NOT NULL UNIQUE,
  state varchar(16) NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','validated','active','retired')),
  parent_id uuid REFERENCES threat_intel.rulesets(id),
  policy jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(policy)='object'),
  checksum char(64) CHECK (checksum ~ '^[0-9a-f]{64}$'),
  created_by uuid NOT NULL REFERENCES commerce.users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  validated_at timestamptz,
  activated_at timestamptz,
  CHECK (state='draft' OR (checksum IS NOT NULL AND validated_at IS NOT NULL))
);
CREATE UNIQUE INDEX rulesets_one_active_idx ON threat_intel.rulesets(state) WHERE state='active';
CREATE TABLE threat_intel.rules (
  ruleset_id uuid NOT NULL REFERENCES threat_intel.rulesets(id),
  rule_id varchar(80) NOT NULL CHECK (rule_id ~ '^RULE_[A-Z0-9_]+$'),
  stage varchar(16) NOT NULL CHECK (stage IN ('input','execution','output','policy')),
  category varchar(16) NOT NULL CHECK (category ~ '^LLM(0[1-9]|10):2025$'),
  kind varchar(16) NOT NULL CHECK (kind IN ('regex','context','structural')),
  pattern text,
  flags varchar(2) NOT NULL DEFAULT '' CHECK (flags IN ('','i','is')),
  action varchar(16) NOT NULL CHECK (action IN ('block','mask','escape','observe')),
  marker varchar(40),
  priority integer NOT NULL DEFAULT 100 CHECK (priority >= 0),
  PRIMARY KEY (ruleset_id, rule_id),
  CHECK (kind <> 'regex' OR (pattern IS NOT NULL AND length(pattern) BETWEEN 1 AND 4096)),
  CHECK (action <> 'mask' OR (stage='output' AND marker IS NOT NULL))
);
CREATE FUNCTION threat_intel.require_draft_ruleset() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE rs uuid; rs_state varchar(16);
BEGIN
  IF TG_OP='DELETE' THEN rs := OLD.ruleset_id; ELSE rs := NEW.ruleset_id; END IF;
  IF TG_OP='UPDATE' AND NEW.ruleset_id <> OLD.ruleset_id THEN
    RAISE EXCEPTION 'rule cannot move to another ruleset';
  END IF;
  SELECT state INTO rs_state FROM threat_intel.rulesets WHERE id=rs FOR UPDATE;
  IF rs_state IS DISTINCT FROM 'draft' THEN RAISE EXCEPTION 'ruleset is immutable'; END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER rules_draft_only BEFORE INSERT OR UPDATE OR DELETE ON threat_intel.rules
FOR EACH ROW EXECUTE FUNCTION threat_intel.require_draft_ruleset();
CREATE FUNCTION threat_intel.freeze_validated_ruleset() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state <> 'draft' AND
    (NEW.policy IS DISTINCT FROM OLD.policy OR NEW.checksum IS DISTINCT FROM OLD.checksum OR
     NEW.version_label IS DISTINCT FROM OLD.version_label OR NEW.parent_id IS DISTINCT FROM OLD.parent_id OR
     NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.validated_at IS DISTINCT FROM OLD.validated_at) THEN
    RAISE EXCEPTION 'validated content is immutable';
  END IF;
  IF OLD.state <> 'draft' AND NEW.state='draft' THEN RAISE EXCEPTION 'clone a new draft'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER rulesets_content_immutable BEFORE UPDATE ON threat_intel.rulesets
FOR EACH ROW EXECUTE FUNCTION threat_intel.freeze_validated_ruleset();
CREATE TABLE threat_intel.policy_publications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ruleset_id uuid NOT NULL REFERENCES threat_intel.rulesets(id),
  previous_id uuid REFERENCES threat_intel.rulesets(id),
  actor_id uuid NOT NULL REFERENCES commerce.users(id),
  request_id uuid NOT NULL,
  outcome varchar(16) NOT NULL CHECK (outcome IN ('published','failed','rolled_back')),
  detail varchar(300) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE commerce.actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES commerce.users(id),
  session_id uuid,
  tool_name varchar(64) NOT NULL CHECK (tool_name IN ('set_cart_item','remove_cart_item','apply_coupon','remove_coupon')),
  target_id uuid NOT NULL,
  arguments jsonb NOT NULL CHECK (jsonb_typeof(arguments)='object' AND NOT (arguments ? 'user_id')),
  arguments_hash char(64) NOT NULL CHECK (arguments_hash ~ '^[0-9a-f]{64}$'),
  base_version integer NOT NULL CHECK (base_version >= 0),
  ruleset_version uuid NOT NULL REFERENCES threat_intel.rulesets(id),
  state varchar(16) NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','executed','cancelled','expired','failed')),
  expires_at timestamptz NOT NULL,
  idempotency_key varchar(128),
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  FOREIGN KEY (target_id, user_id) REFERENCES commerce.carts(id, user_id),
  FOREIGN KEY (session_id, user_id) REFERENCES commerce.chat_sessions(id, user_id),
  CHECK (expires_at > created_at),
  CHECK ((state='pending' AND resolved_at IS NULL) OR (state<>'pending' AND resolved_at IS NOT NULL)),
  CHECK (state<>'executed' OR result IS NOT NULL)
);
CREATE UNIQUE INDEX actions_idempotency_idx ON commerce.actions(user_id, idempotency_key)
WHERE idempotency_key IS NOT NULL;
CREATE INDEX actions_owner_state_idx ON commerce.actions(user_id, state, expires_at);
CREATE FUNCTION commerce.freeze_action_intent() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR
     NEW.session_id IS DISTINCT FROM OLD.session_id OR NEW.tool_name IS DISTINCT FROM OLD.tool_name OR
     NEW.target_id IS DISTINCT FROM OLD.target_id OR NEW.arguments IS DISTINCT FROM OLD.arguments OR
     NEW.arguments_hash IS DISTINCT FROM OLD.arguments_hash OR NEW.base_version IS DISTINCT FROM OLD.base_version OR
     NEW.ruleset_version IS DISTINCT FROM OLD.ruleset_version OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
     NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'action intent is immutable';
  END IF;
  IF OLD.state <> 'pending' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'terminal action is immutable';
  END IF;
  IF OLD.state='pending' AND NEW.state='pending' AND NEW.result IS DISTINCT FROM OLD.result THEN
    RAISE EXCEPTION 'pending preview is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER action_intent_immutable BEFORE UPDATE ON commerce.actions
FOR EACH ROW EXECUTE FUNCTION commerce.freeze_action_intent();
CREATE TABLE audit.outbox (
  event_id uuid PRIMARY KEY,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  delivery_state varchar(16) NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','delivered','dead')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  last_error_code varchar(64),
  CHECK ((delivery_state='delivered' AND delivered_at IS NOT NULL) OR
         (delivery_state<>'delivered' AND delivered_at IS NULL))
);
CREATE INDEX outbox_pending_idx ON audit.outbox(available_at, created_at) WHERE delivery_state='pending';
CREATE TABLE audit.events (
  event_id uuid PRIMARY KEY,
  request_id uuid NOT NULL,
  actor_id uuid REFERENCES commerce.users(id) ON DELETE SET NULL,
  session_id uuid,
  source varchar(16) NOT NULL CHECK (source IN ('web','anythingllm','streamlit','system')),
  api_path varchar(200) NOT NULL,
  model varchar(80),
  status varchar(32) NOT NULL CHECK (status IN ('success','blocked','masked','confirmation_required','error')),
  stage varchar(16) CHECK (stage IN ('input','execution','output','policy')),
  ruleset_version uuid REFERENCES threat_intel.rulesets(id),
  input_chars integer NOT NULL DEFAULT 0 CHECK (input_chars >= 0),
  output_chars integer NOT NULL DEFAULT 0 CHECK (output_chars >= 0),
  input_ms numeric(12,3) NOT NULL DEFAULT 0 CHECK (input_ms >= 0),
  output_ms numeric(12,3) NOT NULL DEFAULT 0 CHECK (output_ms >= 0),
  total_ms numeric(12,3) NOT NULL DEFAULT 0 CHECK (total_ms >= 0),
  summary_redacted varchar(2000) NOT NULL,
  occurred_at timestamptz NOT NULL,
  CHECK ((status='blocked' AND stage IS NOT NULL) OR (status<>'blocked' AND stage IS NULL))
);
CREATE INDEX events_time_idx ON audit.events(occurred_at DESC, event_id);
CREATE INDEX events_status_time_idx ON audit.events(status, occurred_at DESC);
CREATE INDEX events_session_idx ON audit.events(session_id, occurred_at DESC) WHERE session_id IS NOT NULL;
CREATE INDEX events_request_idx ON audit.events(request_id);
CREATE TABLE audit.rule_hits (
  event_id uuid NOT NULL REFERENCES audit.events(event_id) ON DELETE CASCADE,
  rule_id varchar(80) NOT NULL CHECK (rule_id ~ '^RULE_[A-Z0-9_]+$'),
  category varchar(16) NOT NULL CHECK (category ~ '^LLM(0[1-9]|10):2025$'),
  stage varchar(16) NOT NULL CHECK (stage IN ('input','execution','output','policy')),
  action varchar(16) NOT NULL CHECK (action IN ('block','mask','escape','observe')),
  match_count integer NOT NULL CHECK (match_count > 0),
  PRIMARY KEY (event_id, rule_id)
);
CREATE INDEX rule_hits_category_idx ON audit.rule_hits(category, event_id);
CREATE TABLE audit.tool_executions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES audit.events(event_id) ON DELETE CASCADE,
  action_id uuid,
  tool_name varchar(64) NOT NULL,
  outcome varchar(16) NOT NULL CHECK (outcome IN ('read','proposed','executed','denied','error')),
  target_id uuid,
  duration_ms numeric(12,3) NOT NULL CHECK (duration_ms >= 0)
);
CREATE INDEX tool_executions_action_idx ON audit.tool_executions(action_id) WHERE action_id IS NOT NULL;
