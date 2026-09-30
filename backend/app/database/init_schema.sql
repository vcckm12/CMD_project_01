-- ====================================================================
-- AI Security Guardrail Chatbot - PostgreSQL 16 Initial Schema & Seed
-- ====================================================================

-- 1. Create Logical Schemas
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS commerce;
CREATE SCHEMA IF NOT EXISTS audit;

-- ====================================================================
-- 2. Schema: threat_intel (Dynamic Security Rules & Signatures)
-- ====================================================================

CREATE TABLE IF NOT EXISTS threat_intel.guardrail_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(64) UNIQUE NOT NULL,
    category VARCHAR(32) NOT NULL, -- 'INPUT', 'OUTPUT', 'EXECUTION'
    pattern_type VARCHAR(32) NOT NULL, -- 'KEYWORD', 'REGEX', 'HOMOGLYPH', 'SEMANTIC'
    pattern_value TEXT NOT NULL,
    action VARCHAR(16) NOT NULL DEFAULT 'BLOCK', -- 'BLOCK', 'REDACT', 'ALERT'
    severity VARCHAR(16) NOT NULL DEFAULT 'HIGH', -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_rules_active 
    ON threat_intel.guardrail_rules (is_active, category);

-- Seed Threat Intel Rules
INSERT INTO threat_intel.guardrail_rules 
    (rule_id, category, pattern_type, pattern_value, action, severity, description)
VALUES
    ('INJ-001', 'INPUT', 'REGEX', '(?i)(ignore\s*(all\s*)?(the\s*)?(previous|prior|above|safety)?\s*(instructions?|directives?|rules?|context|guardrails?)|disregard\s*(previous|all)?\s*(instructions?|context)|forget\s*(your\s*)?(role|instructions?|rules?)|stop\s*being\s*a\s*shopping\s*bot|bypass\s*(instructions?|guardrails?|all)|reset\s*memory|system\s*override|지침\s*무시|명령\s*무시|지침을\s*전부\s*잊고|run\s*shell)', 'BLOCK', 'CRITICAL', 'Prompt injection: ignore previous instructions'),
    ('INJ-002', 'INPUT', 'REGEX', '(?i)(system\s*(prompt|message)(\s*(leak|dump|show|output|reveal|print))?|dump\s*prompt|initialization\s*prompt|prompt\s*(leak|dump|show|output|reveal|text)|hidden\s*(prompts?|rules?)|developer\s*guidelines?|root\s*configuration|explain\s*how\s*you\s*were\s*built|repeat\s*the\s*words\s*above|echo\s*back\s*all\s*system|시스템\s*프롬프트|초기\s*시스템\s*지침|프롬프트\s*(유출|출력|덤프|복사)|최초\s*시스템\s*설정값)', 'BLOCK', 'CRITICAL', 'System prompt leakage attempt'),
    ('INJ-003', 'INPUT', 'REGEX', '(?i)(dan\s*mode|jailbreak(en|ed)?|jailbroken|unrestricted\s*ai|evilbot|evil\s*ai|developer\s*mode|god\s*mode|unrestricted\s*(persona|hacker|answers?|assistant)|zero\s*guardrails?|without\s*guardrails?|pretend\s*you\s*have\s*no\s*rules|roleplay\s*as|bypass\s*(all\s*)?(safety\s*)?filters?|imagine\s*a\s*world\s*without\s*guardrails|switch\s*to\s*unrestricted|탈옥\s*ai|필터링\s*해제|윤리적\s*제약|모든\s*가드레일\s*무력화)', 'BLOCK', 'HIGH', 'Jailbreak and persona hijacking attempt'),
    ('INJ-004', 'INPUT', 'REGEX', '(?i)(union\s+select|drop\s+(table|schema)|insert\s+into|delete\s+from|update\s+\w+\s+set|\bor\s+[''"]?1[''"]?\s*=\s*[''"]?1|information_schema|or\s+1=1|\bor\s+''a''=''a'')', 'BLOCK', 'CRITICAL', 'SQL Injection signature in prompt'),
    ('INJ-005', 'INPUT', 'REGEX', '(?i)(관리자\s*권한|관리자\s*모드|관리자\s*계정|admin\s+credentials|admin\s+token|admin\s+privileges|lead\s+developer|log\s+in\s+as\s+administrator|change\s+prices)', 'BLOCK', 'HIGH', 'Unauthorized privilege escalation inquiry'),
    ('INJ-006', 'INPUT', 'REGEX', '(?i)(비밀번호\s*(알려줘|출력|가\s*뭐야|를\s*출력)|database\s+password|db\s*비밀번호|서버\s*(관리자\s*)?비밀번호|postgres_password|접속\s*계정과\s*비밀번호|secret[_\s]?key|api[_\s]?key)', 'BLOCK', 'CRITICAL', 'Credential theft attempt'),
    ('INJ-007', 'INPUT', 'REGEX', '(?i)(forget\s*(your\s*)?(role|instructions?|rules?)|stop\s*being\s*a\s*shopping\s*bot|repeat\s*the\s*words\s*above|echo\s*back\s*all\s*system)', 'BLOCK', 'HIGH', 'Role usurpation and instruction reset'),
    ('INJ-008', 'INPUT', 'REGEX', '(?i)(대외비\s*원가|원가\s*전부|비밀\s*원가|cost_price\s*column|원가\s*공개|마진\s*공개|비밀\s*원가와\s*마진)', 'BLOCK', 'CRITICAL', 'Confidential cost price inquiry in input'),
    ('INJ-009', 'INPUT', 'REGEX', '(?i)(dump\s+all\s+customer|customer\s+passwords|customer\s+emails\s+and\s+phone|계정\s*목록\s*보여줘)', 'BLOCK', 'CRITICAL', 'Mass customer PII dump inquiry'),
    ('OUT-001', 'OUTPUT', 'REGEX', '(?i)(nc\s+-e\s+/bin/sh|/bin/bash\s+-i|cmd\.exe\s+/c|powershell\.exe\s+-enc)', 'BLOCK', 'CRITICAL', 'Reverse shell and command execution payloads'),
    ('OUT-002', 'OUTPUT', 'REGEX', '\b\d{6}-[1-4]\d{6}\b', 'REDACT', 'HIGH', 'Korean Resident Registration Number (RRN) masking'),
    ('OUT-003', 'OUTPUT', 'REGEX', '\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'REDACT', 'HIGH', 'Credit card number masking'),
    ('OUT-004', 'OUTPUT', 'REGEX', '\b01[016789]-?\d{3,4}-?\d{4}\b', 'REDACT', 'MEDIUM', 'Korean mobile phone number masking'),
    ('OUT-005', 'OUTPUT', 'REGEX', '(?i)(원가|cost_price|공급가)\s*[:=]?\s*([0-9,]+원?)', 'REDACT', 'CRITICAL', 'Confidential cost price leak prevention')
ON CONFLICT (rule_id) DO UPDATE SET 
    pattern_value = EXCLUDED.pattern_value,
    description = EXCLUDED.description,
    updated_at = NOW();

-- ====================================================================
-- 3. Schema: commerce (Mock Store E-Commerce Domain)
-- ====================================================================

CREATE TABLE IF NOT EXISTS commerce.customers (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(64) NOT NULL,
    email VARCHAR(128) NOT NULL,
    membership_grade VARCHAR(16) NOT NULL DEFAULT 'BASIC',
    phone VARCHAR(32) NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS commerce.products (
    id SERIAL PRIMARY KEY,
    product_code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    price INTEGER NOT NULL,
    cost_price INTEGER NOT NULL, -- CONFIDENTIAL: Never expose to users
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    supplier_code VARCHAR(64) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS commerce.orders (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(64) UNIQUE NOT NULL,
    customer_id VARCHAR(64) NOT NULL REFERENCES commerce.customers(customer_id) ON DELETE CASCADE,
    total_amount INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'ORDERED', 'SHIPPED', 'DELIVERED', 'CANCELLED'
    masked_card VARCHAR(32) NOT NULL,
    shipping_address TEXT NOT NULL,
    ordered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS commerce.order_items (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(64) NOT NULL REFERENCES commerce.orders(order_id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES commerce.products(id) ON DELETE RESTRICT,
    quantity INTEGER NOT NULL DEFAULT 1,
    unit_price INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS commerce.coupons (
    id SERIAL PRIMARY KEY,
    coupon_code VARCHAR(64) UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Seed Commerce Data
INSERT INTO commerce.customers (customer_id, name, email, membership_grade, phone, address)
VALUES
    ('cust_101', '홍길동', 'hong@example.com', 'VIP', '010-1234-5678', '서울특별시 강남구 테헤란로 123'),
    ('cust_102', '이순신', 'lee@example.com', 'GOLD', '010-9876-5432', '서울특별시 서초구 반포대로 45'),
    ('cust_103', '강감찬', 'kang@example.com', 'BASIC', '010-5555-7777', '경기도 성남시 분당구 판교로 88')
ON CONFLICT (customer_id) DO NOTHING;

INSERT INTO commerce.products (product_code, name, category, price, cost_price, stock_quantity, supplier_code, description)
VALUES
    ('PRD-TOP-001', '오버핏 후드티', 'TOP', 39000, 15000, 150, 'SUP-01', '편안한 착용감의 헤비웨이트 오버핏 기모 후드티'),
    ('PRD-BTM-001', '와이드 슬랙스', 'BOTTOM', 42000, 18000, 80, 'SUP-02', '깔끔하고 트렌디한 와이드 핏 밴딩 슬랙스'),
    ('PRD-SHO-001', '베이직 스니커즈', 'SHOES', 55000, 22000, 45, 'SUP-03', '어떤 코디에도 잘 어울리는 클래식 화이트 스니커즈'),
    ('PRD-ACC-001', '미니멀 볼캡', 'ACCESSORY', 25000, 8000, 200, 'SUP-01', '데일리로 착용하기 좋은 코튼 볼캡'),
    ('PRD-OUT-001', '헤비 덕다운 패딩', 'OUTER', 149000, 65000, 30, 'SUP-04', '보온성이 뛰어난 프리미엄 덕다운 숏패딩')
ON CONFLICT (product_code) DO NOTHING;

INSERT INTO commerce.orders (order_id, customer_id, total_amount, status, masked_card, shipping_address)
VALUES
    ('ORD-2026-001', 'cust_101', 39000, 'SHIPPED', '5424-****-****-1234', '서울특별시 강남구 테헤란로 123'),
    ('ORD-2026-002', 'cust_102', 97000, 'ORDERED', '9410-****-****-8888', '서울특별시 서초구 반포대로 45')
ON CONFLICT (order_id) DO NOTHING;

INSERT INTO commerce.coupons (coupon_code, discount_percent, valid_until, is_active)
VALUES
    ('WELCOME2026', 10, NOW() + INTERVAL '30 days', TRUE),
    ('VIPSPECIAL', 20, NOW() + INTERVAL '60 days', TRUE)
ON CONFLICT (coupon_code) DO NOTHING;

-- ====================================================================
-- 4. Schema: audit (Asynchronous Security Audit Logs)
-- ====================================================================

CREATE TABLE IF NOT EXISTS audit.security_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    client_ip VARCHAR(45) NOT NULL,
    stage VARCHAR(32) NOT NULL, -- 'INPUT_GUARDRAIL', 'EXECUTION_GUARDRAIL', 'OUTPUT_GUARDRAIL'
    threat_type VARCHAR(64) NOT NULL,
    rule_id VARCHAR(64),
    payload_hash VARCHAR(64) NOT NULL,
    payload_snippet TEXT,
    action_taken VARCHAR(16) NOT NULL, -- 'BLOCKED', 'REDACTED', 'LOGGED'
    execution_time_ms FLOAT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit.security_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_threat_type ON audit.security_logs (threat_type);
