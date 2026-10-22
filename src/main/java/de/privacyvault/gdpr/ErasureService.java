package de.privacyvault.gdpr;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.config.PrivacyVaultProperties;
import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.crypto.KeyProvider;
import de.privacyvault.security.AuthService;
import de.privacyvault.security.RefreshTokenRepository;
import de.privacyvault.user.UserEntity;
import de.privacyvault.user.UserKeyEntity;
import de.privacyvault.user.UserKeyRepository;
import de.privacyvault.user.UserProfileRepository;
import de.privacyvault.user.UserRepository;
import de.privacyvault.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

@Service
public class ErasureService {
    private final UserRepository users;
    private final UserProfileRepository profiles;
    private final UserKeyRepository keys;
    private final RefreshTokenRepository tokens;
    private final ErasureRequestRepository requests;
    private final ErasureRecordRepository records;
    private final KeyProvider keyProvider;
    private final EncryptionService encryption;
    private final PasswordEncoder passwordEncoder;
    private final PrivacyVaultProperties properties;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public ErasureService(UserRepository users, UserProfileRepository profiles, UserKeyRepository keys,
                          RefreshTokenRepository tokens, ErasureRequestRepository requests,
                          ErasureRecordRepository records, KeyProvider keyProvider,
                          EncryptionService encryption, PasswordEncoder passwordEncoder,
                          PrivacyVaultProperties properties, AuditService audit) {
        this.users = users;
        this.profiles = profiles;
        this.keys = keys;
        this.tokens = tokens;
        this.requests = requests;
        this.records = records;
        this.keyProvider = keyProvider;
        this.encryption = encryption;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.audit = audit;
    }

    @Transactional
    public ErasureDtos.Response request(UUID userId, ErasureDtos.Request input, boolean immediate) {
        UserEntity user = users.findById(userId).orElseThrow(ApiException::notFound);
        if (!passwordEncoder.matches(input.password(), user.getPasswordHash())) throw ApiException.unauthorized();
        if (user.getStatus() != UserStatus.ACTIVE && user.getStatus() != UserStatus.RESTRICTED) {
            throw new ApiException(HttpStatus.CONFLICT, "invalid_account_state", "Account cannot request erasure in its current state");
        }
        Instant now = Instant.now();
        Instant due = immediate ? now : now.plusSeconds(properties.gdpr().erasureGraceDays() * 86_400L);
        byte[] cancellationHash = null;
        String cancellationToken = null;
        if (!immediate) {
            byte[] randomBytes = new byte[32];
            random.nextBytes(randomBytes);
            cancellationToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            cancellationHash = AuthService.sha256(cancellationToken);
            Arrays.fill(randomBytes, (byte) 0);
        }
        String previousStatus = user.getStatus().name();
        user.setStatus(UserStatus.ERASURE_PENDING, now);
        user.incrementTokenVersion(now);
        tokens.findByUserIdAndRevokedAtIsNull(userId).forEach(token -> token.revoke(now));
        requests.save(new ErasureRequestEntity(userId, now, due, previousStatus, cancellationHash));
        audit.record(userId, "ERASURE_REQUEST", "USER", userId, "SUCCESS");
        return new ErasureDtos.Response("PENDING", due, cancellationToken);
    }

    @Transactional
    public void cancel(ErasureDtos.Cancellation input) {
        ErasureRequestEntity request = requests.findLockedByCancelTokenHashAndStatus(
                AuthService.sha256(input.cancellationToken()), "PENDING").orElseThrow(ApiException::notFound);
        Instant now = Instant.now();
        UserEntity user = users.findById(request.getUserId()).orElseThrow(ApiException::notFound);
        if (!request.getScheduledFor().isAfter(now)) throw ApiException.notFound();
        user.setStatus(UserStatus.valueOf(request.getPreviousStatus()), now);
        request.cancel(now);
        audit.record(user.getId(), "ERASURE_CANCELLED", "USER", user.getId(), "SUCCESS");
    }

    @Scheduled(fixedDelayString = "PT60S")
    @Transactional
    public void completeDueRequests() {
        Instant now = Instant.now();
        requests.findDueForUpdate("PENDING", now).forEach(request -> {
            if (users.existsById(request.getUserId())) {
                completeUserErasure(request.getUserId(), now);
                audit.record(request.getUserId(), "ERASURE_COMPLETED", "USER", request.getUserId(), "SUCCESS");
            }
        });
    }

    @Transactional
    public void completeImmediately(UUID userId) {
        ErasureRequestEntity request = requests.findFirstByUserIdAndStatusOrderByRequestedAtDesc(userId, "PENDING")
                .orElse(null);
        if (request == null) throw ApiException.notFound();
        completeUserErasure(userId, Instant.now());
        audit.record(userId, "ERASURE_COMPLETED", "USER", userId, "SUCCESS");
    }

    private void completeUserErasure(UUID userId, Instant now) {
        UserKeyEntity key = keys.findById(userId).orElseThrow(ApiException::notFound);
        keyProvider.destroy(userId, key.getExternalKeyRef());
        records.save(new ErasureRecordEntity(encryption.pseudonym("erasure-proof", userId.toString()), now));
        profiles.deleteById(userId);
        users.deleteById(userId);
    }
}
