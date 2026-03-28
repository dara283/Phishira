-- Phishara Database Schema (MySQL)
-- Run: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS phishara CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishara;

CREATE TABLE IF NOT EXISTS scan_records (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    input_value VARCHAR(2048) NOT NULL,
    input_type  VARCHAR(20) NOT NULL COMMENT 'url | email | phone',
    risk_score  FLOAT DEFAULT 0.0,
    risk_level  VARCHAR(20) DEFAULT 'unknown' COMMENT 'safe | low | medium | high | critical',
    details     JSON,
    ip_address  VARCHAR(64),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_input_type (input_type),
    INDEX idx_risk_level (risk_level),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    indicator      VARCHAR(2048) NOT NULL,
    indicator_type VARCHAR(20) NOT NULL,
    threat_type    VARCHAR(100),
    source         VARCHAR(100),
    confidence     FLOAT DEFAULT 0.0,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_indicator (indicator(255)),
    INDEX idx_indicator_type (indicator_type)
) ENGINE=InnoDB;
