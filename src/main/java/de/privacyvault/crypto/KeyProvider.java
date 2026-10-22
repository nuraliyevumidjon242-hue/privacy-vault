package de.privacyvault.crypto;

import java.util.UUID;

public interface KeyProvider {
    WrappedKey wrap(UUID userId, byte[] dek);
    byte[] unwrap(UUID userId, WrappedKey key);
    void destroy(UUID userId, String externalKeyRef);
    String activeKeyVersion();

    record WrappedKey(byte[] ciphertext, String externalKeyRef, String version) {
        public WrappedKey {
            ciphertext = ciphertext.clone();
        }
        @Override public byte[] ciphertext() { return ciphertext.clone(); }
    }
}
