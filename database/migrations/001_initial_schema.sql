-- ====================================================================
-- AI Security Guardrail Chatbot - Migration 001_initial_schema.sql
-- ====================================================================

-- 1. Create Logical Schemas
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS commerce;
CREATE SCHEMA IF NOT EXISTS audit;

-- 2. Threat Intel Rules Table
CREATE TABLE IF NOT EXISTS threat_intel.guardrail_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(64) UNIQUE NOT NULL,
    category VARCHAR(32) NOT NULL,
    pattern_type VARCHAR(32) NOT NULL,
    pattern_value TEXT NOT NULL,
    action VARCHAR(16) NOT NULL DEFAULT 'BLOCK',
    severity VARCHAR(16) NOT NULL DEFAULT 'HIGH',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_rules_active 
    ON threat_intel.guardrail_rules (is_active, category);

-- 3. Commerce Tables
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
    cost_price INTEGER NOT NULL,
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
    status VARCHAR(32) NOT NULL,
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

-- 4. Audit Table
CREATE TABLE IF NOT EXISTS audit.security_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    client_ip VARCHAR(45) NOT NULL,
    stage VARCHAR(32) NOT NULL,
    threat_type VARCHAR(64) NOT NULL,
    rule_id VARCHAR(64),
    payload_hash VARCHAR(64) NOT NULL,
    payload_snippet TEXT,
    action_taken VARCHAR(16) NOT NULL,
    execution_time_ms FLOAT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit.security_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_threat_type ON audit.security_logs (threat_type);
