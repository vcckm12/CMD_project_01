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
    ('INJ-001', 'INPUT', 'REGEX', '(?i)(ignore\s+(all\s+)?previous\s+instructions?|system\s+prompt\s*(leak|dump|show)|지침\s*무시|프롬프트\s*출력)', 'BLOCK', 'CRITICAL', 'Prompt injection & System prompt extraction'),
    ('INJ-002', 'INPUT', 'KEYWORD', 'dan mode', 'BLOCK', 'HIGH', 'Jailbreak DAN persona pattern'),
    ('INJ-003', 'INPUT', 'KEYWORD', 'jailbreak', 'BLOCK', 'HIGH', 'Jailbreak keyword attempt'),
    ('INJ-004', 'INPUT', 'REGEX', '(?i)(union\s+select|drop\s+table|insert\s+into|\bor\s+1=1\b)', 'BLOCK', 'CRITICAL', 'SQL Injection signatures in user prompt'),
    ('INJ-005', 'INPUT', 'KEYWORD', '관리자 권한', 'BLOCK', 'HIGH', 'Unauthorized privilege escalation inquiry'),
    ('INJ-006', 'INPUT', 'KEYWORD', '비밀번호 알려줘', 'BLOCK', 'CRITICAL', 'Credential theft attempt'),
    ('OUT-001', 'OUTPUT', 'REGEX', '(?i)(nc\s+-e\s+/bin/sh|/bin/bash\s+-i|cmd\.exe\s+/c|powershell\.exe\s+-enc)', 'BLOCK', 'CRITICAL', 'Reverse shell and command execution payloads'),
    ('OUT-002', 'OUTPUT', 'REGEX', '\b\d{6}-[1-4]\d{6}\b', 'REDACT', 'HIGH', 'Korean Resident Registration Number (RRN) masking'),
    ('OUT-003', 'OUTPUT', 'REGEX', '\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'REDACT', 'HIGH', 'Credit card number masking'),
    ('OUT-004', 'OUTPUT', 'REGEX', '\b01[016789]-?\d{3,4}-?\d{4}\b', 'REDACT', 'MEDIUM', 'Korean mobile phone number masking'),
    ('OUT-005', 'OUTPUT', 'REGEX', '(?i)(원가|cost_price|공급가)\s*[:=]?\s*([0-9,]+원?)', 'REDACT', 'CRITICAL', 'Confidential cost price leak prevention')
ON CONFLICT (rule_id) DO NOTHING;

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
