package de.privacyvault.gdpr;

import de.privacyvault.audit.AuditLogRepository;
import de.privacyvault.consent.ConsentRepository;
import de.privacyvault.config.PrivacyVaultProperties;
import de.privacyvault.security.RefreshTokenEntity;
import de.privacyvault.security.RefreshTokenRepository;
import de.privacyvault.user.UserEntity;
import de.privacyvault.user.UserRepository;
import de.privacyvault.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RetentionSchedulerTest {
    @Test
    void deletesExpiredRefreshTokens() {
        RefreshTokenRepository tokens = mock(RefreshTokenRepository.class);
        RetentionScheduler scheduler = scheduler(tokens, mock(AuditLogRepository.class),
                mock(UserRepository.class), mock(ConsentRepository.class),
                mock(ErasureRecordRepository.class), mock(JdbcTemplate.class), properties(730));
        scheduler.cleanExpiredRefreshTokens();
        verify(tokens).deleteExpiredBefore(any(Instant.class));
    }

    @Test
    void enablesRetentionContextBeforeDeletingAppendOnlyEvidence() {
        AuditLogRepository audit = mock(AuditLogRepository.class);
        ConsentRepository consents = mock(ConsentRepository.class);
        ErasureRecordRepository records = mock(ErasureRecordRepository.class);
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(String.class))).thenReturn("on");
        RetentionScheduler scheduler = scheduler(mock(RefreshTokenRepository.class), audit,
                mock(UserRepository.class), consents, records, jdbc, properties(730));

        scheduler.cleanupRetainedEvidence();

        verify(jdbc, times(2)).queryForObject(anyString(), eq(String.class));
        verify(audit).deleteOlderThan(any(Instant.class));
        verify(consents).deleteOlderThan(any(Instant.class));
        verify(records).deleteOlderThan(any(Instant.class));
    }

    @Test
    void inactivatesDormantUsersAndRevokesTheirRefreshTokens() {
        UserRepository users = mock(UserRepository.class);
        RefreshTokenRepository tokens = mock(RefreshTokenRepository.class);
        Instant lastLogin = Instant.now().minus(Duration.ofDays(10));
        UUID userId = UUID.randomUUID();
        UserEntity user = new UserEntity(userId, new byte[]{1}, new byte[]{2}, "argon2", lastLogin);
        RefreshTokenEntity token = new RefreshTokenEntity(userId, new byte[]{3},
                UUID.randomUUID(), Instant.now().plus(Duration.ofDays(1)), Instant.now());
        when(users.findAllByStatusAndLastLoginAtBefore(eq(UserStatus.ACTIVE), any(Instant.class),
                any(Pageable.class))).thenReturn(new PageImpl<>(List.of(user)), new PageImpl<>(List.of()));
        when(tokens.findByUserIdAndRevokedAtIsNull(userId)).thenReturn(List.of(token));
        RetentionScheduler scheduler = scheduler(tokens, mock(AuditLogRepository.class), users,
                mock(ConsentRepository.class), mock(ErasureRecordRepository.class),
                mock(JdbcTemplate.class), properties(0));

        scheduler.inactivateLongDormantAccounts();

        assertEquals(UserStatus.INACTIVE, user.getStatus());
        assertEquals(1, user.getTokenVersion());
        assertNotNull(token.getRevokedAt());
        verify(tokens).findByUserIdAndRevokedAtIsNull(userId);
    }

    private static RetentionScheduler scheduler(RefreshTokenRepository tokens, AuditLogRepository audit,
                                                UserRepository users, ConsentRepository consents,
                                                ErasureRecordRepository records, JdbcTemplate jdbc,
                                                PrivacyVaultProperties properties) {
        return new RetentionScheduler(tokens, audit, users, consents, records, properties, jdbc);
    }

    private static PrivacyVaultProperties properties(int inactiveDays) {
        return new PrivacyVaultProperties(
                new PrivacyVaultProperties.Crypto("", "", "", "env", "eu-central-1", "v1"),
                new PrivacyVaultProperties.Jwt("", "test", Duration.ofMinutes(15), Duration.ofDays(7)),
                new PrivacyVaultProperties.Gdpr(14, 365, inactiveDays, 1095, 365),
                new PrivacyVaultProperties.Cors(List.of("http://localhost")));
    }
}
