package de.privacyvault.crypto;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.DisableKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.KeyState;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.DecryptRequest;

import java.util.Map;
import java.util.UUID;

public final class AwsKmsKeyProvider implements KeyProvider {
    private final KmsClient client;
    private final String activeKeyVersion;

    public AwsKmsKeyProvider(KmsClient client, String rotationEpoch) {
        this.client = client;
        if (rotationEpoch == null || !rotationEpoch.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("KMS rotation epoch must be a safe version identifier");
        }
        this.activeKeyVersion = "aws-kms:" + rotationEpoch;
    }

    @Override
    public String activeKeyVersion() {
        return activeKeyVersion;
    }

    @Override
    public WrappedKey wrap(UUID userId, byte[] dek) {
        String keyId = client.createKey(CreateKeyRequest.builder()
                        .description("PrivacyVault per-user DEK wrapping key")
                        .keySpec(KeySpec.SYMMETRIC_DEFAULT)
                        .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                        .build())
                .keyMetadata().keyId();
        try {
            byte[] ciphertext = client.encrypt(EncryptRequest.builder()
                                    .keyId(keyId)
                                    .encryptionAlgorithm(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT)
                                    .encryptionContext(Map.of("user_id", userId.toString()))
                                    .plaintext(SdkBytes.fromByteArray(dek))
                                    .build())
                            .ciphertextBlob().asByteArray();
            return new WrappedKey(ciphertext, keyId, activeKeyVersion + ":" + keyId);
        } catch (RuntimeException exception) {
            client.scheduleKeyDeletion(ScheduleKeyDeletionRequest.builder()
                            .keyId(keyId).pendingWindowInDays(7).build());
            throw exception;
        }
    }

    @Override
    public byte[] unwrap(UUID userId, WrappedKey key) {
        return client.decrypt(DecryptRequest.builder()
                        .keyId(key.externalKeyRef())
                        .ciphertextBlob(SdkBytes.fromByteArray(key.ciphertext()))
                        .encryptionContext(Map.of("user_id", userId.toString()))
                        .build())
                .plaintext().asByteArray();
    }

    @Override
    public void destroy(UUID userId, String externalKeyRef) {
        var metadata = client.describeKey(DescribeKeyRequest.builder().keyId(externalKeyRef).build()).keyMetadata();
        if (metadata.keyState() == KeyState.PENDING_DELETION) return;
        if (metadata.keyState() != KeyState.DISABLED) {
            client.disableKey(DisableKeyRequest.builder().keyId(externalKeyRef).build());
        }
        client.scheduleKeyDeletion(ScheduleKeyDeletionRequest.builder()
                .keyId(externalKeyRef)
                .pendingWindowInDays(7)
                .build());
    }
}
