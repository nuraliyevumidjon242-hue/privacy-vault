package de.privacyvault.security;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.config.PrivacyVaultProperties;
import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.crypto.KeyProvider;
import de.privacyvault.user.UserEntity;
import de.privacyvault.user.UserKeyEntity;
import de.privacyvault.user.UserProfileEntity;
import de.privacyvault.user.UserProfileRepository;
import de.privacyvault.user.UserKeyRepository;
import de.privacyvault.user.UserRepository;
import de.privacyvault.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
public class AuthService {
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final List<String> COMMON_PASSWORDS = List.of(
            "password123!", "Password123!", "123456789012", "qwerty123456", "letmein123456");
    private final UserRepository users;
    private final UserKeyRepository keys;
    private final UserProfileRepository profiles;
    private final RefreshTokenRepository refreshTokens;
    private final EncryptionService encryption;
    private final de.privacyvault.crypto.KeyProvider keyProvider;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final PrivacyVaultProperties properties;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();
    private final String dummyPasswordHash;

    public AuthService(UserRepository users, UserKeyRepository keys, UserProfileRepository profiles,
                       RefreshTokenRepository refreshTokens, EncryptionService encryption,
                       de.privacyvault.crypto.KeyProvider keyProvider,
                       PasswordEncoder passwordEncoder, JwtService jwtService,
                       PrivacyVaultProperties properties, AuditService audit) {
        this.users = users;
        this.keys = keys;
        this.profiles = profiles;
        this.refreshTokens = refreshTokens;
        this.encryption = encryption;
        this.keyProvider = keyProvider;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.properties = properties;
        this.audit = audit;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public AuthDtos.TokenResponse register(AuthDtos.RegisterRequest input) {
        String email = normalize(input.email());
        if (COMMON_PASSWORDS.stream().anyMatch(p -> p.equalsIgnoreCase(input.password()))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "weak_password",
                    "Choose a password that is not commonly used");
        }
        byte[] emailIndex = encryption.blindIndex(email);
        if (users.findByEmailBlindIndex(emailIndex).isPresent()) {
            throw new ApiException(HttpStatus.CONFLICT, "registration_unavailable",
                    "Registration could not be completed");
        }
        UUID id = UUID.randomUUID();
        byte[] dek = encryption.generateDek();
        KeyProvider.WrappedKey wrapped = encryption.wrapDek(id, dek);
        Instant now = Instant.now();
        try {
            UserEntity user = users.save(new UserEntity(id, encryption.encrypt(id, "email", email, dek),
                    emailIndex, passwordEncoder.encode(input.password()), now));
            keys.save(new UserKeyEntity(id, wrapped.ciphertext(), wrapped.externalKeyRef(), wrapped.version(), now));
            profiles.save(new UserProfileEntity(id, now));
            AuthDtos.TokenResponse tokens = issueTokens(user, UUID.randomUUID());
            audit.record(id, "REGISTER", "USER", id, "SUCCESS");
            return tokens;
        } catch (RuntimeException exception) {
            try { keyProvider.destroy(id, wrapped.externalKeyRef()); }
            catch (RuntimeException cleanupFailure) { exception.addSuppressed(cleanupFailure); }
            throw exception;
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    @Transactional(noRollbackFor = ApiException.class)
    public AuthDtos.TokenResponse login(AuthDtos.LoginRequest input) {
        String email = normalize(input.email());
        UserEntity user = users.findByEmailBlindIndex(encryption.blindIndex(email)).orElse(null);
        Instant now = Instant.now();
        String candidateHash = user == null ? dummyPasswordHash : user.getPasswordHash();
        boolean passwordMatches = passwordEncoder.matches(input.password(), candidateHash);
        if (user == null || user.getStatus() == UserStatus.ERASURE_PENDING || user.getStatus() == UserStatus.ERASED
                || user.getStatus() == UserStatus.RESTRICTED
                || (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null
                && user.getLockedUntil().isAfter(now))
                || !passwordMatches) {
            if (user != null && user.getStatus() != UserStatus.ERASURE_PENDING
                    && user.getStatus() != UserStatus.ERASED && user.getStatus() != UserStatus.RESTRICTED) {
                user.failedLogin(now, user.getFailedLoginAttempts() + 1 >= MAX_FAILED_ATTEMPTS);
                users.save(user);
            }
            audit.record(null, "LOGIN", "AUTHENTICATION", null, "FAILURE");
            throw ApiException.unauthorized();
        }
        user.successfulLogin(now);
        UUID family = UUID.randomUUID();
        AuthDtos.TokenResponse tokens = issueTokens(user, family);
        audit.record(user.getId(), "LOGIN", "AUTHENTICATION", user.getId(), "SUCCESS");
        return tokens;
    }

    @Transactional(noRollbackFor = ApiException.class)
    public AuthDtos.TokenResponse refresh(String rawToken) {
        byte[] hash = sha256(rawToken);
        RefreshTokenEntity token = refreshTokens.findLockedByTokenHash(hash).orElse(null);
        Instant now = Instant.now();
        if (token == null) {
            audit.record(null, "REFRESH", "TOKEN", null, "FAILURE");
            throw ApiException.unauthorized();
        }
        if (token.getRevokedAt() != null) {
            refreshTokens.findByFamilyIdAndRevokedAtIsNull(token.getFamilyId()).forEach(t -> t.revoke(now));
            users.findById(token.getUserId()).ifPresent(user -> user.incrementTokenVersion(now));
            audit.record(token.getUserId(), "REFRESH_REUSE", "TOKEN_FAMILY", null, "REJECTED");
            throw ApiException.unauthorized();
        }
        UserEntity user = users.findById(token.getUserId()).orElse(null);
        if (!token.isUsable(now) || user == null || user.getStatus() != UserStatus.ACTIVE) {
            token.revoke(now);
            audit.record(token.getUserId(), "REFRESH", "TOKEN", null, "FAILURE");
            throw ApiException.unauthorized();
        }
        token.revoke(now);
        return issueTokens(user, token.getFamilyId());
    }

    @Transactional
    public void logout(String rawToken) {
        refreshTokens.findLockedByTokenHash(sha256(rawToken)).ifPresent(token -> token.revoke(Instant.now()));
    }

    @Transactional
    public void logoutAll(UUID userId) {
        Instant now = Instant.now();
        refreshTokens.findByUserIdAndRevokedAtIsNull(userId).forEach(token -> token.revoke(now));
        users.findById(userId).ifPresent(user -> user.incrementTokenVersion(now));
        audit.record(userId, "LOGOUT_ALL", "AUTHENTICATION", userId, "SUCCESS");
    }

    private AuthDtos.TokenResponse issueTokens(UserEntity user, UUID familyId) {
        Instant now = Instant.now();
        Instant accessExpiry = now.plus(properties.jwt().accessTtl());
        Instant refreshExpiry = now.plus(properties.jwt().refreshTtl());
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String rawRefresh = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        refreshTokens.save(new RefreshTokenEntity(user.getId(), sha256(rawRefresh), familyId, refreshExpiry, now));
        return new AuthDtos.TokenResponse(jwtService.issue(user), rawRefresh, accessExpiry, refreshExpiry);
    }

    public static String normalize(String email) {
        return email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    public static byte[] sha256(String raw) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
