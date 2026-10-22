package de.privacyvault.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Component
public class StartupConfigurationValidator implements ApplicationRunner {
    private final PrivacyVaultProperties properties;
    private final Environment environment;

    public StartupConfigurationValidator(PrivacyVaultProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (environment.matchesProfiles("prod")) {
            validateProductionConfiguration();
        }
        if ("env".equals(properties.crypto().keyProvider())) {
            decodeKey(properties.crypto().masterKey(), "PRIVACYVAULT_MASTER_KEY");
        }
        decodeKey(properties.crypto().blindIndexKey(), "PRIVACYVAULT_BLIND_INDEX_KEY");
        decodeKey(properties.crypto().pseudonymKey(), "PRIVACYVAULT_PSEUDONYM_KEY");
        decodeKey(properties.jwt().secret(), "PRIVACYVAULT_JWT_SECRET");
    }

    private void validateProductionConfiguration() {
        if (!"aws-kms".equals(properties.crypto().keyProvider())) {
            throw new IllegalStateException("Production requires KEY_PROVIDER=aws-kms");
        }
        List<String> origins = properties.cors().allowedOrigins();
        if (origins == null || origins.isEmpty()) {
            throw new IllegalStateException("Production requires explicit HTTPS CORS origins");
        }
        for (String origin : origins) {
            validateProductionOrigin(origin);
        }
        if (environment.getProperty("springdoc.swagger-ui.enabled", Boolean.class, false)
                || environment.getProperty("springdoc.api-docs.enabled", Boolean.class, false)) {
            throw new IllegalStateException("OpenAPI documentation must be disabled in production");
        }
    }

    private static void validateProductionOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            throw new IllegalStateException("Production CORS origins must not be blank");
        }
        try {
            URI uri = URI.create(origin);
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null
                    || uri.getUserInfo() != null
                    || uri.getPort() == 0
                    || uri.getPort() > 65_535
                    || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())
                    || uri.getRawQuery() != null
                    || uri.getRawFragment() != null
                    || origin.contains("*")) {
                throw new IllegalStateException(
                        "Production CORS origins must be explicit HTTPS origins without paths or wildcards");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Production CORS origin is not a valid HTTPS origin", exception);
        }
    }

    private static byte[] decodeKey(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be configured");
        }
        try {
            byte[] decoded = HexFormat.of().parseHex(value);
            if (decoded.length < 32) throw new IllegalStateException(name + " must contain at least 32 random bytes (64 hex characters)");
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(name + " must be 64 hexadecimal characters", e);
        }
    }
}
