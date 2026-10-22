package de.privacyvault.crypto;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.user.UserKeyEntity;
import de.privacyvault.user.UserKeyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class KeyRotationTest {
    @Test
    void rotationWorkerPersistsNewWrappedKeyAndErasesPlainDekBuffer() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        EncryptionService encryption = mock(EncryptionService.class);
        KeyProvider provider = mock(KeyProvider.class);
        UUID userId = UUID.randomUUID();
        byte[] dek = new byte[32];
        UserKeyEntity key = new UserKeyEntity(userId, new byte[]{1}, "old-key", "old-v1", Instant.now());
        when(keys.findById(userId)).thenReturn(Optional.of(key));
        when(encryption.unwrapDek(userId, key.getWrappedDek(), "old-key", "old-v1")).thenReturn(dek);
        when(encryption.wrapDek(userId, dek))
                .thenReturn(new KeyProvider.WrappedKey(new byte[]{2, 3}, "new-key", "new-v2"));

        KeyRotationWorker worker = new KeyRotationWorker(keys, encryption, provider);
        var result = worker.rotate(userId);

        assertEquals("old-key", result.oldKeyRef());
        assertEquals("new-key", result.newKeyRef());
        assertArrayEquals(new byte[]{2, 3}, key.getWrappedDek());
        assertEquals("new-v2", key.getKekVersion());
        assertArrayEquals(new byte[32], dek);
        verify(keys).saveAndFlush(key);
        verify(provider, never()).destroy(any(), anyString());
    }

    @Test
    void rotationWorkerCleansNewKmsKeyWhenPersistenceFails() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        EncryptionService encryption = mock(EncryptionService.class);
        KeyProvider provider = mock(KeyProvider.class);
        UUID userId = UUID.randomUUID();
        UserKeyEntity key = new UserKeyEntity(userId, new byte[]{1}, "old-key", "old-v1", Instant.now());
        when(keys.findById(userId)).thenReturn(Optional.of(key));
        when(encryption.unwrapDek(any(), any(), anyString(), anyString())).thenReturn(new byte[32]);
        when(encryption.wrapDek(any(), any()))
                .thenReturn(new KeyProvider.WrappedKey(new byte[]{2}, "new-key", "new-v2"));
        when(keys.saveAndFlush(key)).thenThrow(new IllegalStateException("database unavailable"));

        KeyRotationWorker worker = new KeyRotationWorker(keys, encryption, provider);
        assertThrows(IllegalStateException.class, () -> worker.rotate(userId));
        verify(provider).destroy(userId, "new-key");
    }

    @Test
    void keyRotationIsRejectedForSharedEnvironmentKey() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        KeyRotationWorker worker = mock(KeyRotationWorker.class);
        AuditService audit = mock(AuditService.class);
        KeyRotationService service = new KeyRotationService(keys, mock(EnvKeyProvider.class), worker, audit);
        assertEquals("rotation_unavailable", assertThrows(ApiException.class,
                () -> service.rotateAll(UUID.randomUUID())).code());
        verifyNoInteractions(keys, worker, audit);
    }

    @Test
    void keyRotationPagesKmsKeysAndAuditsTheOperation() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        KeyRotationWorker worker = mock(KeyRotationWorker.class);
        AuditService audit = mock(AuditService.class);
        KeyProvider provider = mock(AwsKmsKeyProvider.class);
        when(provider.activeKeyVersion()).thenReturn("aws-kms:v2");
        UUID adminId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        UserKeyEntity key = new UserKeyEntity(userId, new byte[]{1}, "old-key", "old-v1", Instant.now());
        when(keys.findAllByDestroyedAtIsNull(any(Pageable.class))).thenReturn(
                new PageImpl<>(List.of(key), PageRequest.of(0, 100, Sort.by("userId")), 1));
        when(worker.rotate(userId)).thenReturn(new KeyRotationWorker.RotationResult(userId, "old-key", "new-key"));

        int count = new KeyRotationService(keys, provider, worker, audit).rotateAll(adminId);

        assertEquals(1, count);
        verify(provider).destroy(userId, "old-key");
        verify(audit).record(adminId, "KEY_ROTATION", "USER_KEYS", null, "SUCCESS");
    }

    @Test
    void keyRotationHandlesAnEmptyKeyStore() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        KeyRotationWorker worker = mock(KeyRotationWorker.class);
        AuditService audit = mock(AuditService.class);
        KeyProvider provider = mock(AwsKmsKeyProvider.class);
        when(provider.activeKeyVersion()).thenReturn("aws-kms:v2");
        UUID adminId = UUID.randomUUID();
        when(keys.findAllByDestroyedAtIsNull(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        assertEquals(0, new KeyRotationService(keys, provider, worker, audit).rotateAll(adminId));
        verify(audit).record(adminId, "KEY_ROTATION", "USER_KEYS", null, "SUCCESS");
    }

    @Test
    void repeatedKmsRotationSkipsKeysAlreadyOnTheActiveEpoch() {
        UserKeyRepository keys = mock(UserKeyRepository.class);
        KeyRotationWorker worker = mock(KeyRotationWorker.class);
        AuditService audit = mock(AuditService.class);
        KeyProvider provider = mock(AwsKmsKeyProvider.class);
        when(provider.activeKeyVersion()).thenReturn("aws-kms:v2");
        UserKeyEntity key = new UserKeyEntity(UUID.randomUUID(), new byte[]{1}, "kms-key",
                "aws-kms:v2:kms-key", Instant.now());
        when(keys.findAllByDestroyedAtIsNull(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(key), PageRequest.of(0, 100), 1));

        assertEquals(0, new KeyRotationService(keys, provider, worker, audit).rotateAll(UUID.randomUUID()));
        verifyNoInteractions(worker);
        verify(provider, never()).destroy(any(), anyString());
    }

    @Test
    void adminControllerReturnsRotatedKeyCount() {
        KeyRotationService service = mock(KeyRotationService.class);
        UUID adminId = UUID.randomUUID();
        when(service.rotateAll(adminId)).thenReturn(3);
        AdminKeyRotationController controller = new AdminKeyRotationController(service);
        assertEquals(java.util.Map.of("rotatedKeys", 3), controller.rotate(adminId));
        verify(service).rotateAll(adminId);
    }
}
