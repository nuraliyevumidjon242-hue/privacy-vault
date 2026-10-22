package de.privacyvault.crypto;

import de.privacyvault.user.UserKeyEntity;
import de.privacyvault.user.UserKeyRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.UUID;

@Component
public class KeyRotationWorker {
    private final UserKeyRepository keys;
    private final EncryptionService encryption;
    private final KeyProvider keyProvider;

    public KeyRotationWorker(UserKeyRepository keys, EncryptionService encryption, KeyProvider keyProvider) {
        this.keys = keys;
        this.encryption = encryption;
        this.keyProvider = keyProvider;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RotationResult rotate(UUID userId) {
        UserKeyEntity key = keys.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User key disappeared during rotation"));
        String oldRef = key.getExternalKeyRef();
        byte[] dek = encryption.unwrapDek(userId, key.getWrappedDek(), oldRef, key.getKekVersion());
        KeyProvider.WrappedKey replacement = null;
        try {
            replacement = encryption.wrapDek(userId, dek);
            key.replaceWrappedDek(replacement.ciphertext(), replacement.externalKeyRef(), replacement.version());
            keys.saveAndFlush(key);
            return new RotationResult(userId, oldRef, replacement.externalKeyRef());
        } catch (RuntimeException exception) {
            if (replacement != null) {
                try { keyProvider.destroy(userId, replacement.externalKeyRef()); }
                catch (RuntimeException cleanupFailure) { exception.addSuppressed(cleanupFailure); }
            }
            throw exception;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    public record RotationResult(UUID userId, String oldKeyRef, String newKeyRef) {}
}
