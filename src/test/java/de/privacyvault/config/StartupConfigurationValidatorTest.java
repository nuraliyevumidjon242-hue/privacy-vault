package de.privacyvault.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StartupConfigurationValidatorTest {
    private static final String KEY = "ab".repeat(32);

    @Test
    void productionRejectsEnvironmentKeyProvider() {
        var validator = validator("env", List.of("https://app.example.com"), true);

        assertThrows(IllegalStateException.class,
                () -> validator.run(new DefaultApplicationArguments()));
    }

    @Test
    void productionRejectsInsecureOrWildcardCorsOrigins() {
        for (String origin : List.of("http://app.example.com", "*", "https://*.example.com",
                "https://user@app.example.com", "https://app.example.com/path",
                "https://app.example.com:0", "https://app.example.com:65536")) {
            var validator = validator("aws-kms", List.of(origin), true);

            assertThrows(IllegalStateException.class,
                    () -> validator.run(new DefaultApplicationArguments()), origin);
        }
    }

    @Test
    void productionAcceptsKmsAndExplicitHttpsOrigins() {
        var validator = validator("aws-kms",
                List.of("https://app.example.com", "https://admin.example.com"), false);

        assertDoesNotThrow(() -> validator.run(new DefaultApplicationArguments()));
    }

    @Test
    void productionRequiresCorsOriginsAndDisabledApiDocumentation() {
        var noOrigins = validator("aws-kms", List.of(), true);
        assertThrows(IllegalStateException.class,
                () -> noOrigins.run(new DefaultApplicationArguments()));

        var swaggerEnabled = validator("aws-kms", List.of("https://app.example.com"), true, true);
        assertThrows(IllegalStateException.class,
                () -> swaggerEnabled.run(new DefaultApplicationArguments()));
    }

    private static StartupConfigurationValidator validator(String keyProvider, List<String> origins,
                                                            boolean production) {
        return validator(keyProvider, origins, production, false);
    }

    private static StartupConfigurationValidator validator(String keyProvider, List<String> origins,
                                                            boolean production, boolean swaggerEnabled) {
        var properties = new PrivacyVaultProperties(
                new PrivacyVaultProperties.Crypto("", KEY, KEY, keyProvider, "eu-central-1", "v1"),
                new PrivacyVaultProperties.Jwt(KEY, "privacy-vault", java.time.Duration.ofMinutes(15),
                        java.time.Duration.ofDays(7)),
                new PrivacyVaultProperties.Gdpr(14, 365, 730, 1095, 365),
                new PrivacyVaultProperties.Cors(origins));
        var environment = new MockEnvironment();
        if (production) environment.setActiveProfiles("prod");
        if (swaggerEnabled) environment.setProperty("springdoc.swagger-ui.enabled", "true");
        return new StartupConfigurationValidator(properties, environment);
    }
}
