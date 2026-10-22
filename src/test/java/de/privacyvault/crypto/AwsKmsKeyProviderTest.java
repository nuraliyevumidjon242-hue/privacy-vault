package de.privacyvault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.DisableKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KeyState;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AwsKmsKeyProviderTest {
    private KmsClient client;
    private AwsKmsKeyProvider provider;

    @BeforeEach
    void setUp() {
        client = mock(KmsClient.class);
        provider = new AwsKmsKeyProvider(client, "v1");
    }

    @Test
    void createsUserBoundKmsKeyAndWrapsTheDek() {
        UUID userId = UUID.randomUUID();
        byte[] dek = new byte[32];
        byte[] encrypted = new byte[]{7, 8, 9};
        when(client.createKey(any(CreateKeyRequest.class))).thenReturn(
                CreateKeyResponse.builder().keyMetadata(KeyMetadata.builder().keyId("kms-key").build()).build());
        when(client.encrypt(any(EncryptRequest.class))).thenReturn(
                EncryptResponse.builder().ciphertextBlob(SdkBytes.fromByteArray(encrypted)).build());
        when(client.decrypt(any(DecryptRequest.class))).thenReturn(
                DecryptResponse.builder().plaintext(SdkBytes.fromByteArray(dek)).build());

        KeyProvider.WrappedKey wrapped = provider.wrap(userId, dek);
        assertArrayEquals(encrypted, wrapped.ciphertext());
        assertEquals("kms-key", wrapped.externalKeyRef());
        assertEquals("aws-kms:v1:kms-key", wrapped.version());
        assertArrayEquals(dek, provider.unwrap(userId, wrapped));

        var encryptCaptor = org.mockito.ArgumentCaptor.forClass(EncryptRequest.class);
        verify(client).encrypt(encryptCaptor.capture());
        assertEquals(userId.toString(), encryptCaptor.getValue().encryptionContext().get("user_id"));
        var decryptCaptor = org.mockito.ArgumentCaptor.forClass(DecryptRequest.class);
        verify(client).decrypt(decryptCaptor.capture());
        assertEquals(userId.toString(), decryptCaptor.getValue().encryptionContext().get("user_id"));
    }

    @Test
    void schedulesCreationCleanupWhenKmsEncryptionFails() {
        when(client.createKey(any(CreateKeyRequest.class))).thenReturn(
                CreateKeyResponse.builder().keyMetadata(KeyMetadata.builder().keyId("orphan-key").build()).build());
        when(client.encrypt(any(EncryptRequest.class))).thenThrow(new IllegalStateException("KMS unavailable"));
        assertThrows(IllegalStateException.class, () -> provider.wrap(UUID.randomUUID(), new byte[32]));
        verify(client).scheduleKeyDeletion(argThat((ScheduleKeyDeletionRequest request) ->
                "orphan-key".equals(request.keyId()) && request.pendingWindowInDays() == 7));
    }

    @Test
    void destroyIsIdempotentForPendingDeletionKeys() {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(
                DescribeKeyResponse.builder().keyMetadata(
                        KeyMetadata.builder().keyState(KeyState.PENDING_DELETION).build()).build());
        provider.destroy(UUID.randomUUID(), "kms-key");
        verify(client, never()).disableKey(any(DisableKeyRequest.class));
        verify(client, never()).scheduleKeyDeletion(any(ScheduleKeyDeletionRequest.class));
    }

    @Test
    void disablesEnabledKeysBeforeSchedulingDeletion() {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(
                DescribeKeyResponse.builder().keyMetadata(
                        KeyMetadata.builder().keyState(KeyState.ENABLED).build()).build());
        provider.destroy(UUID.randomUUID(), "kms-key");
        verify(client).disableKey(any(DisableKeyRequest.class));
        verify(client).scheduleKeyDeletion(argThat((ScheduleKeyDeletionRequest request) ->
                "kms-key".equals(request.keyId()) && request.pendingWindowInDays() == 7));
    }

    @Test
    void doesNotDisableAnAlreadyDisabledKeyAgain() {
        when(client.describeKey(any(DescribeKeyRequest.class))).thenReturn(
                DescribeKeyResponse.builder().keyMetadata(
                        KeyMetadata.builder().keyState(KeyState.DISABLED).build()).build());
        provider.destroy(UUID.randomUUID(), "kms-key");
        verify(client, never()).disableKey(any(DisableKeyRequest.class));
        verify(client).scheduleKeyDeletion(any(ScheduleKeyDeletionRequest.class));
    }
}
