CREATE TABLE users (
    id UUID PRIMARY KEY,
    email_encrypted BYTEA NOT NULL,
    email_blind_index BYTEA NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
    status VARCHAR(24) NOT NULL CHECK (status IN ('ACTIVE', 'ERASURE_PENDING', 'RESTRICTED', 'LOCKED', 'INACTIVE', 'ERASED')),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    token_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    first_name BYTEA,
    last_name BYTEA,
    phone BYTEA,
    address BYTEA,
    date_of_birth BYTEA,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek BYTEA NOT NULL,
    external_key_ref VARCHAR(512) NOT NULL,
    kek_version VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    destroyed_at TIMESTAMPTZ
);

CREATE TABLE consents (
    id UUID PRIMARY KEY,
    event_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    subject_ref BYTEA NOT NULL,
    purpose VARCHAR(100) NOT NULL,
    policy_version VARCHAR(64) NOT NULL,
    action VARCHAR(16) NOT NULL CHECK (action IN ('GRANTED', 'WITHDRAWN')),
    ip_hash BYTEA,
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_consents_subject_sequence ON consents(subject_ref, event_sequence DESC);
CREATE INDEX idx_consents_retention ON consents(recorded_at);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expiry ON refresh_tokens(expires_at);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    actor_ref VARCHAR(128) NOT NULL,
    action VARCHAR(80) NOT NULL,
    resource_type VARCHAR(80) NOT NULL,
    resource_ref VARCHAR(128),
    result VARCHAR(24) NOT NULL,
    request_id VARCHAR(128) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_audit_log_occurred_at ON audit_log(occurred_at);
CREATE INDEX idx_audit_log_actor_time ON audit_log(actor_ref, occurred_at DESC);

CREATE FUNCTION privacyvault_append_only_guard() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting(TG_ARGV[0], true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Append-only privacy evidence cannot be modified';
END;
$$;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION privacyvault_append_only_guard('privacyvault.audit_retention_cleanup');
CREATE TRIGGER consents_append_only
    BEFORE UPDATE OR DELETE ON consents
    FOR EACH ROW EXECUTE FUNCTION privacyvault_append_only_guard('privacyvault.consent_retention_cleanup');

CREATE TABLE erasure_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    previous_status VARCHAR(24) NOT NULL DEFAULT 'ACTIVE',
    cancel_token_hash BYTEA,
    cancelled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status VARCHAR(16) NOT NULL CHECK (status IN ('PENDING', 'CANCELLED', 'COMPLETED'))
);
CREATE INDEX idx_erasure_due ON erasure_requests(status, scheduled_for);

CREATE TABLE erasure_records (
    id UUID PRIMARY KEY,
    subject_hash BYTEA NOT NULL,
    erased_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_erasure_records_retention ON erasure_records(erased_at);
