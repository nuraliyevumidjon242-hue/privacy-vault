# Production deployment preparation

This is a single-host Docker Compose deployment template, not a managed or
high-availability service. It has not been deployed to a cloud environment.
Do not use real personal data until the operator checklist below is complete.

## Included safeguards

- `compose.production.yml` keeps PostgreSQL off published host ports and binds
  the API to loopback so a host reverse proxy can be the only public entry.
- PostgreSQL has a persistent named volume and a readiness check. The API waits
  for PostgreSQL, runs Flyway migrations, uses a read-only root filesystem,
  drops Linux capabilities, and has resource and log limits.
- The production Spring profile requires explicit HTTPS CORS origins, disables
  Swagger/OpenAPI, and uses AWS KMS instead of the local environment KEK.
- Database, JWT, blind-index, and pseudonym keys are mounted as Compose secrets
  from files outside the repository. No secret values belong in the env file.
- The API has a separate outbound network for KMS; PostgreSQL is only attached
  to the isolated data network.
- The Nginx example terminates TLS, redirects HTTP to HTTPS, and replaces
  forwarded client headers with values observed by the proxy.

The application currently has process-local authentication rate limits and
scheduled jobs. Run exactly one API replica. Do not scale it horizontally
without shared rate limiting and coordinated/distributed scheduled-job
execution. The sample AWS KMS adapter creates a customer-managed key per user;
review account quotas, cost, IAM permissions, deletion behavior, and recovery
at the intended scale first.

## Host setup

1. Use a hardened Linux host with Docker Engine and the Compose plugin, a DNS
   name, and Nginx 1.25.1 or newer managed outside this Compose stack; the host
   does not need a separate JDK installation.
2. Issue and install a valid TLS certificate for the DNS name. Configure the
   host firewall to expose only TCP ports 80 and 443; keep PostgreSQL and the
   API port inaccessible from remote networks.
3. Create a host-only production env file from `.env.production.example`.
   Set the release image tag, database name/user, AWS region, exact frontend
   origins, and the host reverse-proxy address. Keep the env file out of the
   repository.
4. Create the four secret files named `postgres_password`, `jwt_secret`,
   `blind_index_key`, and `pseudonym_key` in `SECRET_DIR`. Use independent
   cryptographically random values; the three application keys must each be
   at least 32 random bytes encoded as 64 hexadecimal characters. On the Linux
   host, restrict the containing directory to the deployment operator (mode
   `0700`) and set the secret files to mode `0444` so both the API's UID 10001
   and the PostgreSQL container can read the shared password file. With
   rootless Docker, the directory owner must also be the user running the
   daemon. The host directory restriction prevents other host users from
   reaching the source files; Compose file-backed secrets preserve source-file
   permissions in the container. Confirm both services can read their mounted
   files before opening public traffic.
   Back up key material separately from the database and rehearse its recovery.
5. Provision an AWS workload identity restricted to the KMS actions and
   resources actually used by `AwsKmsKeyProvider`. Make AWS SDK credentials
   available through the host/workload identity chain; do not put static AWS
   access keys in Compose, the image, or source control. Confirm the container
   can reach the identity endpoint and the configured KMS region.
6. Copy `deploy/nginx/privacyvault.conf.example` to the host Nginx
   configuration, replace both example hostnames and certificate paths, test
   the Nginx configuration, then reload Nginx. The sample assumes Nginx is
   running on the same host and proxies to `127.0.0.1:8080`.
7. Review the exact changes and image source, then from the project root:

   ```sh
   docker compose --env-file .env.production -f compose.production.yml config
   docker compose --env-file .env.production -f compose.production.yml build
   docker compose --env-file .env.production -f compose.production.yml up -d
   docker compose --env-file .env.production -f compose.production.yml ps
   ```

   The API must start with the `prod` profile. Verify the public HTTPS health
   endpoint, registration/login and a synthetic account's export/erasure flow.
   Do not test against real user data.

## Backup, migration, and rollback

Backups are not configured by this project. Before every release, take an
encrypted PostgreSQL backup, verify that it can be restored into an isolated
environment, and confirm that the required KMS keys and secret files remain
available. Store backups and key material under separately controlled access.

Flyway migrations run automatically at application startup. Review every new
migration and rehearse it against a restored copy of production data before
release. There is no automatic schema rollback: if a migration or release
fails, stop traffic, preserve logs, and restore the tested database backup
along with a compatible application image and key material. Never point an
older image at a changed schema without confirming compatibility.

## Operator-owned release gates

- Establish and test database backup retention, encryption, restore time, and
  recovery-point objectives.
- Select and test an administrator provisioning/review process; the application
  deliberately has no public admin-role assignment endpoint.
- Configure host monitoring, disk/volume alerts, log retention/access, incident
  ownership, patching, and a tested rollback procedure.
- Review CORS origins, data purposes/lawful bases, notices, retention values,
  processor agreements, and any required DPIA with the responsible controller.
- Run the OWASP dependency scan with an approved NVD API key and review
  findings before release.
- Verify KMS rotation, erasure, account quota alarms, and recovery in a
  non-production AWS account. KMS key deletion is delayed; it is not an
  instantaneous erasure guarantee.

Passing the local test suite or using this template is not a security,
availability, or legal-compliance certification.
