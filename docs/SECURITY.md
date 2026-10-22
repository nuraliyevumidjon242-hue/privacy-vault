# Security design, threat model and operations

## Scope and assumptions

The API assumes TLS is terminated by a trusted reverse proxy or cloud ingress. Application containers are not exposed directly to the public internet. Secrets are delivered through a secret manager/environment injection and never committed. PostgreSQL and KMS access use least-privilege identities. The sample is a portfolio demonstration; conduct a deployment-specific threat assessment before processing real data.

## STRIDE summary

| Threat | Example | Mitigation / residual risk |
|---|---|---|
| Spoofing | Stolen password or forged access token | Argon2id; signed short-lived JWT; persistent token-version/status check; refresh-token hash, rotation and family reuse detection; no MFA/email verification in sample |
| Tampering | Ciphertext, profile, consent or request altered | AES-GCM tag and user/field AAD; DTO validation; consent write API appends events; database access is a privileged trust boundary |
| Repudiation | User disputes consent or a sensitive action | Append-oriented audit and consent event tables, request ID, timestamps; DB administrators remain a trust boundary; no independent trusted timestamping |
| Information disclosure | Database snapshot or API authorization error | Per-user DEK; encrypted email/profile fields; HMAC blind index; authenticated `/me` operations; no entity serialization; audit avoids request bodies |
| Denial of service | Credential stuffing, expensive password hashing | Bucket4j IP rate limits and temporary lockout; bounded in-memory bucket cache; add shared distributed throttling, ingress limits and capacity monitoring for multiple replicas |
| Elevation of privilege | User accesses another account, admin decrypts user data | User ID from validated JWT, no caller-supplied user identifier in `/me`; ADMIN-only audit/key operations; no admin decryption endpoint; role assignment is operationally protected |

## Key management

### Data encryption

Each account has a random 256-bit DEK. AES-256-GCM uses a fresh 96-bit IV for each field write. The envelope stores format version, crypto version, IV and ciphertext/tag. AAD binds the user UUID and field name. Never reuse an IV with the same key. Email ciphertext remains encrypted; login lookup uses a deterministic HMAC-SHA256 blind index under a dedicated key. Consent, IP, audit and erasure references use a different pseudonym key and purpose-separated HMAC inputs to reduce cross-purpose linkage.

### Local development

`KEY_PROVIDER=env` reads a 32-byte hex master key from `PRIVACYVAULT_MASTER_KEY`. The wrapped DEK is encrypted under this shared KEK. Deleting the wrapped DEK from the live database is **not** backup-safe erasure if an older backup contains it and the KEK is available. Protect local `.env` and backups; the setup script creates random values.

### Production KMS

Set `KEY_PROVIDER=aws-kms`, configure `AWS_REGION`, and provide AWS credentials using the workload's IAM role (ECS task role, EKS workload identity, or EC2 instance profile). Do not bake credentials into an image or pass them in source control. The adapter creates a distinct AWS KMS symmetric key for each user and encrypts the DEK with user UUID as KMS encryption context.

On erasure, the adapter disables the KMS key immediately and schedules deletion. AWS KMS enforces a minimum 7-day pending-deletion period; while pending, ciphertext cannot be decrypted because the key is disabled, but permanent destruction is not instantaneous. Verify AWS KMS quotas, account/region limits, cost, CloudTrail visibility, deletion permissions and recovery procedures before choosing this per-user-key model at scale.

### Rotation and recovery

`AWS_KMS_ROTATION_EPOCH` identifies the active wrapping-key generation. `POST /api/v1/admin/keys/rotate` uses the configured KMS provider to create a new per-user key, decrypt/re-wrap each DEK, persist the new reference, then disable/schedule the old key. Increment the epoch (for example `v1` to `v2`) through a controlled deployment before triggering rotation. Keys already on the active epoch are skipped, so retries are idempotent. Rotation is batched in pages of 100. The environment provider deliberately rejects automated rotation; its manual secret change requires a controlled rewrap migration.

Before planned rotation:

1. Verify KMS permissions and alerting; test with a non-production account.
2. Take an encrypted, access-controlled database backup and confirm the rollback window.
3. Run rotation from an approved admin identity and capture the returned count and request/audit reference.
4. Verify representative users can access their own data and inspect KMS state.
5. Keep old KMS keys enabled only for the documented rollback window, then disable/schedule deletion under a reviewed change.

The sample does not implement a durable KMS-operation outbox. If a KMS call succeeds and the database transaction fails, or cleanup of an old key fails after the new reference commits, operators must inspect KMS and database state before retrying. A production system should add an idempotent key-operation journal/outbox and reconciliation job.

## Technical and organizational measures (TOMs)

- **Confidentiality:** encryption at rest at field level, TLS assumption, Argon2id password storage, no plaintext refresh tokens in the database, role-based administration, restricted secrets, keyed hashes rather than raw IP addresses for consent evidence.
- **Integrity:** AEAD authentication, field AAD, input validation, database constraints, versioned migrations, request IDs and audit metadata. PostgreSQL triggers reject updates/deletes to audit and consent evidence except in the retention-cleanup transaction.
- **Availability/resilience:** PostgreSQL backups, health endpoint, key-recovery procedures and CI tests are deployment requirements; this repository does not provision a backup policy or disaster recovery service.
- **Access control:** least privilege for app/database/KMS identities; admin role assignment via a protected operational process; periodic access reviews and MFA for operator accounts are required.
- **Client tokens:** keep access tokens in memory where possible, refresh tokens in an OS-protected secure store, and never put bearer tokens in URLs, browser local storage, analytics or logs. A browser deployment should prefer a carefully designed `HttpOnly`, `Secure`, `SameSite` cookie/BFF pattern with CSRF protection rather than persisting tokens in JavaScript storage.
- **Data minimization:** fields are optional; no raw IP is stored in consent history; log event values are allow-listed metadata.
- **Review:** dependency scanning in CI, tests for crypto tampering and erasure, and a documented OWASP review checklist.

## Incident and breach response outline (Article 33)

1. **Contain:** on-call operator limits access, preserves relevant logs/CloudTrail evidence, rotates compromised credentials/keys where safe, and prevents further disclosure.
2. **Assess promptly:** identify affected processing, data categories, approximate subject counts, timelines, likely consequences and whether confidentiality/integrity/availability was impacted.
3. **Document:** preserve a dated incident record, decisions, uncertainty and mitigation steps with restricted access; do not put personal data or secrets in issue trackers or chat.
4. **Notify decision:** controller/DPO evaluates GDPR Article 33 and, where required, notifies the competent supervisory authority without undue delay and within 72 hours of awareness. If late, document reasons.
5. **Notify individuals:** where the breach is likely to result in a high risk, assess Article 34 communication without undue delay, subject to applicable exceptions.
6. **Recover and learn:** validate containment, restore only from trustworthy backups, rotate exposed credentials, address root cause, and update the risk assessment and procedures.

The application does not automatically detect or report breaches. The controller/DPO remains responsible for legal determinations and communication.

## OWASP ASVS / Top 10 review checklist

- **ASVS V2 / A07 Identification and Authentication Failures:** password floor, Argon2id, generic login errors, lockout, rate limiting, short access JWT, refresh rotation/reuse detection. Still needed: MFA, email verification, recovery flow and distributed throttling.
- **ASVS V3 / A01 Broken Access Control:** identity-derived `/me` scope, status checks, ADMIN routes isolated, no admin data-decryption API. Add authorization tests for each new route.
- **ASVS V5 / A03 Injection:** JPA parameterization and validated DTOs. Review any future raw SQL, template or shell use.
- **ASVS V6 / A02 Cryptographic Failures:** JCA AES-GCM, random IVs, AAD, unique per-user DEKs, separated HMAC key, external KMS option. Review KMS rotation/deletion semantics and backups.
- **ASVS V7 / A09 Logging and Monitoring Failures:** audit metadata omits secret/personal values; retention job exists. Add alerting, protected centralized logs, integrity controls and tested incident escalation.
- **ASVS V8 / A08 Software and Data Integrity Failures:** Maven dependency check and CI; pin/verify release provenance, protect CI credentials and deployment artifacts.
- **ASVS V14 / A05 Security Misconfiguration:** secure response headers, constrained CORS, no stack traces in API errors, non-root/read-only API container. TLS and production configuration remain deployment tasks.
- **A04 Insecure Design / A06 Vulnerable and Outdated Components / A10 SSRF:** review new flows, update dependencies, and avoid adding unrestricted outbound URL fetches.
- **A09 Security Logging and Monitoring Failures / A10 SSRF (OWASP Top 10 2021):** use the threat model above; test operational telemetry without collecting personal payloads.

Use the current OWASP ASVS release as the formal checklist baseline before release; this document is a mapping, not a claim that all ASVS controls pass.
