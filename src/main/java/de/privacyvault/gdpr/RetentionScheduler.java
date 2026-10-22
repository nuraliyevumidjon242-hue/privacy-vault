package de.privacyvault.gdpr;

import de.privacyvault.audit.AuditLogRepository;
import de.privacyvault.consent.ConsentRepository;
import de.privacyvault.config.PrivacyVaultProperties;
import de.privacyvault.gdpr.ErasureRecordRepository;
import de.privacyvault.security.RefreshTokenRepository;
import de.privacyvault.user.UserRepository;
import de.privacyvault.user.UserStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;

@Component
public class RetentionScheduler {
    private final RefreshTokenRepository tokens;
    private final AuditLogRepository audit;
    private final UserRepository users;
    private final ConsentRepository consents;
    private final ErasureRecordRepository erasureRecords;
    private final PrivacyVaultProperties properties;
    private final JdbcTemplate jdbc;

    public RetentionScheduler(RefreshTokenRepository tokens, AuditLogRepository audit, UserRepository users,
                              ConsentRepository consents, ErasureRecordRepository erasureRecords,
                              PrivacyVaultProperties properties, JdbcTemplate jdbc) {
        this.tokens = tokens;
        this.audit = audit;
        this.users = users;
        this.consents = consents;
        this.erasureRecords = erasureRecords;
        this.properties = properties;
        this.jdbc = jdbc;
    }

    @Scheduled(fixedDelayString = "PT6H")
    @Transactional
    public void cleanExpiredRefreshTokens() {
        tokens.deleteExpiredBefore(Instant.now());
    }

    @Scheduled(cron = "0 30 3 * * *", zone = "UTC")
    @Transactional
    public void cleanupRetainedEvidence() {
        jdbc.queryForObject(
                "select set_config('privacyvault.audit_retention_cleanup', 'on', true)", String.class);
        jdbc.queryForObject(
                "select set_config('privacyvault.consent_retention_cleanup', 'on', true)", String.class);
        audit.deleteOlderThan(Instant.now().minusSeconds(properties.gdpr().auditRetentionDays() * 86_400L));
        consents.deleteOlderThan(Instant.now().minusSeconds(
                properties.gdpr().consentRetentionDays() * 86_400L));
        erasureRecords.deleteOlderThan(Instant.now().minusSeconds(
                properties.gdpr().erasureProofRetentionDays() * 86_400L));
    }

    @Scheduled(cron = "0 0 4 * * *", zone = "UTC")
    @Transactional
    public void inactivateLongDormantAccounts() {
        Instant now = Instant.now();
        Instant cutoff = now.minusSeconds(properties.gdpr().inactiveAccountDays() * 86_400L);
        while (true) {
            var batch = users.findAllByStatusAndLastLoginAtBefore(UserStatus.ACTIVE, cutoff,
                    PageRequest.of(0, 200));
            if (batch.isEmpty()) break;
            batch.forEach(user -> {
                user.markInactive(now);
                tokens.findByUserIdAndRevokedAtIsNull(user.getId()).forEach(token -> token.revoke(now));
            });
        }
    }
}
