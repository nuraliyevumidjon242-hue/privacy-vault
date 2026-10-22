package de.privacyvault.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfiguration {
    @Bean
    OpenAPI privacyVaultOpenApi() {
        return new OpenAPI().info(new Info()
                .title("PrivacyVault API")
                .version("v1")
                .description("GDPR-oriented API for encrypted personal data, consent, access, portability and erasure.")
                .contact(new Contact().name("PrivacyVault maintainers")));
    }
}
