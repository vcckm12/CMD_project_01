-- D-36: every guardrail layer runs and records its own verdict, so each event shows which layers would
-- have blocked (rules, LLM judge) and how much time each took. No user text is stored.
ALTER TABLE audit.events
  ADD COLUMN layers jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(layers) = 'object'),
  ADD COLUMN model_ms numeric(12,3) NOT NULL DEFAULT 0 CHECK (model_ms >= 0);
