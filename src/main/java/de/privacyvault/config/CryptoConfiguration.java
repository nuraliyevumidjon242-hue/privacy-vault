package de.privacyvault.config;

import de.privacyvault.crypto.AwsKmsKeyProvider;
import de.privacyvault.crypto.EnvKeyProvider;
import de.privacyvault.crypto.KeyProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

@Configuration
public class CryptoConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "privacyvault.crypto", name = "key-provider", havingValue = "env", matchIfMissing = true)
    KeyProvider envKeyProvider(PrivacyVaultProperties properties) {
        return new EnvKeyProvider(properties.crypto().masterKey());
    }

    @Bean
    @ConditionalOnProperty(prefix = "privacyvault.crypto", name = "key-provider", havingValue = "aws-kms")
    KmsClient kmsClient(PrivacyVaultProperties properties) {
        return KmsClient.builder().region(Region.of(properties.crypto().awsRegion())).build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "privacyvault.crypto", name = "key-provider", havingValue = "aws-kms")
    KeyProvider awsKmsKeyProvider(KmsClient client, PrivacyVaultProperties properties) {
        return new AwsKmsKeyProvider(client, properties.crypto().awsKmsRotationEpoch());
    }
}
