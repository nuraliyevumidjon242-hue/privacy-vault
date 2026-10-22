# PrivacyVault database model

```mermaid
erDiagram
    USERS ||--|| USER_PROFILES : has
    USERS ||--|| USER_KEYS : protected_by
    USERS ||--o{ REFRESH_TOKENS : owns
    USERS ||--o{ ERASURE_REQUESTS : requests
    USERS { UUID id PK; bytea email_encrypted; bytea email_blind_index UK; varchar password_hash; varchar role; varchar status; timestamp created_at }
    USER_PROFILES { UUID user_id PK_FK; bytea first_name; bytea last_name; bytea phone; bytea address; bytea date_of_birth }
    USER_KEYS { UUID user_id PK_FK; bytea wrapped_dek; varchar external_key_ref; varchar kek_version; timestamp destroyed_at }
    CONSENTS { UUID id PK; bigint event_sequence UK; bytea subject_ref; varchar purpose; varchar policy_version; varchar action; bytea ip_hash; timestamp recorded_at }
    REFRESH_TOKENS { UUID id PK; UUID user_id FK; bytea token_hash UK; UUID family_id; timestamp expires_at; timestamp revoked_at }
    AUDIT_LOG { UUID id PK; varchar actor_ref; varchar action; varchar resource_type; varchar resource_ref; varchar result; varchar request_id; timestamp occurred_at }
    ERASURE_REQUESTS { UUID id PK; UUID user_id FK; timestamp scheduled_for; timestamp cancelled_at; timestamp completed_at; varchar status }
    ERASURE_RECORDS { UUID id PK; bytea subject_hash; timestamp erased_at }
```

Consent, audit and erasure records are deliberately not linked to the deleted user's row. Consent and audit tables reject updates/deletes except for the scheduled retention transaction; their pseudonymous references still require access and retention controls.
