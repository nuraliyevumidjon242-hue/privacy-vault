# GDPR / DSGVO implementation map

This is an engineering map, not legal advice or a compliance certificate. The controller must determine purposes, lawful bases, retention, notices, processor roles and whether a DPIA is required.

| GDPR article | Implementation in PrivacyVault | Important limitation / operational action |
|---|---|---|
| 5 — Principles | Encrypted-at-rest personal fields, minimized optional profile fields, audit metadata minimization, configurable retention jobs for audit (365 days), consent (1095 days) and erasure proof (365 days), pseudonymous evidence | Verify purpose limitation, accuracy, retention and accountability in the real deployment and privacy notice |
| 6 — Lawfulness | No lawful basis is hard-coded; purpose registration is documented in the register | Controller must choose and document a lawful basis per purpose before processing |
| 7 — Consent | Append-only `consents` rows record purpose, policy version, grant/withdrawal, timestamp and keyed IP hash | Consent is not treated as the lawful basis for every feature; legal review and withdrawal UX are required |
| 15 — Access | `GET /api/v1/users/me/data` decrypts and returns the caller's data and processing/retention information | Verify response completeness, identity assurance and exemptions for a real controller |
| 16 — Rectification | `PATCH /api/v1/users/me` validates and re-encrypts changed fields using fresh IVs | Email rectification is not exposed in the sample; add a verified email-change workflow |
| 17 — Erasure | `DELETE /api/v1/users/me` deactivates and invalidates sessions, provides a cancellable configurable grace period; `?immediate=true` skips it; due jobs remove personal rows and destroy/disable the DEK wrapping key | AWS KMS disables immediately but irreversible key deletion is scheduled at least 7 days later. Local shared-KEK mode cannot prove old backup erasure. Legal exceptions and downstream copies need controller procedures |
| 18 — Restriction | `PATCH /api/v1/users/me/restriction` blocks profile changes and new consent grants while permitting necessary account storage and data-subject actions | Add purpose-specific processing gates if additional business processing is introduced |
| 20 — Portability | `GET /api/v1/users/me/export` returns machine-readable JSON | CSV and third-party transfer are not implemented |
| 25 — Data protection by design/default | Optional fields, opaque UUIDs, field encryption, strict authenticated `/me` scope, secure headers, minimal DTOs | Review deployment defaults, logs, backups, admin processes and UI defaults |
| 30 — Records of processing | Filled example in [PROCESSING-ACTIVITIES.md](./PROCESSING-ACTIVITIES.md) | Controller must replace example owner/contact/retention assumptions with actual facts |
| 32 — Security of processing | AES-GCM, Argon2id, token rotation/revocation, rate limiting, lockout, restricted admin surface, audit metadata, HTTPS assumption | Conduct a deployment-specific risk assessment, key custody review, restore test and access review |
| 33 — Personal data breach notification | Incident response outline in [SECURITY.md](./SECURITY.md) covers assessment, evidence and the 72-hour supervisory-authority decision | This code does not detect, classify or notify breaches automatically; controller owns statutory decisions and notifications |

## Technical evidence

- Database schema: `src/main/resources/db/migration/V1__initial_schema.sql`.
- Personal-data encryption and domain-separated HMACs: `crypto.EncryptionService`; per-user key wrapping contract: `crypto.KeyProvider`.
- Authentication and authorization: `security` package and `config.SecurityConfiguration`.
- Access/export/rectification: `user.UserController` and `user.UserDataService`.
- Consent history: `consent` package; rows are append-only through the application API.
- Restriction and erasure: `gdpr` package.
- Audit events and retention: `audit` package and `gdpr.RetentionScheduler`.
- OpenAPI: `/v3/api-docs` and [openapi.yaml](./openapi.yaml). Swagger UI is not bundled because its embedded DOMPurify version has known vulnerabilities.
