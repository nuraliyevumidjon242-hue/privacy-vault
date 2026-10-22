package de.privacyvault.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "privacyvault")
public record PrivacyVaultProperties(Crypto crypto, Jwt jwt, Gdpr gdpr, Cors cors) {
    public record Crypto(String masterKey, String blindIndexKey, String pseudonymKey, String keyProvider,
                         String awsRegion, String awsKmsRotationEpoch) {}
    public record Jwt(String secret, String issuer, Duration accessTtl, Duration refreshTtl) {}
    public record Gdpr(int erasureGraceDays, int auditRetentionDays, int inactiveAccountDays,
                       int consentRetentionDays, int erasureProofRetentionDays) {}
    public record Cors(List<String> allowedOrigins) {}
}
