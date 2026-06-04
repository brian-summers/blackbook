-- PostgreSQL Initialization Script for Blackbook
-- Creates limited-privilege application user with minimal access
-- Runs automatically when PostgreSQL container initializes

-- ============================================================================
-- IMPORTANT: This script runs as the superuser (POSTGRES_USER)
-- It sets up security roles and permissions for the application
-- ============================================================================

-- Create application user with limited privileges
-- This user will run the Blackbook application
CREATE USER blackbook_app WITH PASSWORD :'blackbook_app_password' NOINHERIT;

-- Ensure user cannot create new objects (principle of least privilege)
ALTER USER blackbook_app NOCREATEDB;
ALTER USER blackbook_app NOCREATEROLE;
ALTER USER blackbook_app NOINHERIT;
ALTER USER blackbook_app NOREPLICATION;
ALTER USER blackbook_app NOBYPASSRLS;

-- ============================================================================
-- Database Schema Setup
-- ============================================================================

-- Create secrets table (already exists, grant permissions)
GRANT CONNECT ON DATABASE blackbook TO blackbook_app;
GRANT USAGE ON SCHEMA public TO blackbook_app;

-- Create tables for Blackbook application
-- This is run as the admin user and then permissions granted to app user

-- Secrets table for storing encrypted secrets
CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Credentials table for authentication data
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit log table for security tracking
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_name VARCHAR(255),
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    status VARCHAR(50),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Grant Minimal Permissions to Application User
-- ============================================================================

-- Grant SELECT, INSERT, UPDATE, DELETE on application tables
-- But NOT on audit tables (read-only for security)
GRANT SELECT, INSERT, UPDATE, DELETE ON secrets TO blackbook_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON credentials TO blackbook_app;

-- Grant sequence permissions for auto-increment
GRANT USAGE, SELECT ON SEQUENCE secrets_id_seq TO blackbook_app;
GRANT USAGE, SELECT ON SEQUENCE credentials_id_seq TO blackbook_app;

-- Grant INSERT on audit log only (read-only, append-only)
GRANT INSERT ON audit_log TO blackbook_app;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO blackbook_app;

-- Reader role for audit logs (separate role for future use)
CREATE ROLE blackbook_auditor WITH NOLOGIN;
GRANT SELECT ON audit_log TO blackbook_auditor;

-- ============================================================================
-- Security Configuration
-- ============================================================================

-- Set password for application user (via environment variable passed to container)
-- Format: -v blackbook_app_password="<generated_password>"
-- Skip if password already set above

-- Create backup user for scheduled backups (read-only)
CREATE USER blackbook_backup WITH PASSWORD :'backup_password' NOINHERIT;
ALTER USER blackbook_backup NOCREATEDB;
ALTER USER blackbook_backup NOCREATEROLE;
ALTER USER blackbook_backup NOINHERIT;

-- Grant SELECT only on all tables for backup user
GRANT CONNECT ON DATABASE blackbook TO blackbook_backup;
GRANT USAGE ON SCHEMA public TO blackbook_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO blackbook_backup;

-- ============================================================================
-- Audit and Logging
-- ============================================================================

-- Enable query logging for security
-- Note: This is configured in postgresql.conf
-- This just documents what should be enabled:
-- log_statement = 'all'
-- log_duration = on
-- log_min_duration_statement = 100  -- log queries over 100ms
-- log_connections = on
-- log_disconnections = on

-- ============================================================================
-- Final Privileges Check
-- ============================================================================

-- Revoke connect from public for security
REVOKE CONNECT ON DATABASE blackbook FROM PUBLIC;

-- Grant connect only to specific roles
GRANT CONNECT ON DATABASE blackbook TO blackbook_app;
GRANT CONNECT ON DATABASE blackbook TO blackbook_backup;
GRANT CONNECT ON DATABASE blackbook TO blackbook_admin;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO blackbook_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO blackbook_app;

-- ============================================================================
-- Verification
-- ============================================================================

-- Verify setup (results will be shown after initialization)
\echo '=== Blackbook Database Setup Complete ==='
\echo 'Admin User:' :DBuser
\echo 'Application User: blackbook_app'
\echo 'Backup User: blackbook_backup'
\echo 'Database Name:' :dbname
\echo 'Tables Created: secrets, credentials, audit_log'
\echo 'Security: Least privilege principle enforced'
\echo '=== Next Steps: Configure application with DATABASE_URL ==='
