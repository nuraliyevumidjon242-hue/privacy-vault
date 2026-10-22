package de.privacyvault.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.UUID;

public final class EnvKeyProvider implements KeyProvider {
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private final byte[] masterKey;
    private final SecureRandom random = new SecureRandom();

    public EnvKeyProvider(String masterKeyHex) {
        try {
            this.masterKey = HexFormat.of().parseHex(masterKeyHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("PRIVACYVAULT_MASTER_KEY must be hexadecimal", e);
        }
        if (masterKey.length != 32) throw new IllegalStateException("PRIVACYVAULT_MASTER_KEY must be exactly 32 bytes");
    }

    @Override
    public WrappedKey wrap(UUID userId, byte[] dek) {
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(masterKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(userId.toString().getBytes(StandardCharsets.UTF_8));
            byte[] encrypted = cipher.doFinal(dek);
            return new WrappedKey(ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array(),
                    "env:" + userId, "env-v1");
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Unable to wrap data encryption key", e);
        }
    }

    @Override
    public byte[] unwrap(UUID userId, WrappedKey key) {
        byte[] value = key.ciphertext();
        if (value.length < IV_LENGTH + 16) throw new CryptoOperationException("Wrapped key is invalid");
        byte[] iv = new byte[IV_LENGTH];
        byte[] encrypted = new byte[value.length - IV_LENGTH];
        System.arraycopy(value, 0, iv, 0, iv.length);
        System.arraycopy(value, IV_LENGTH, encrypted, 0, encrypted.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(masterKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(userId.toString().getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Unable to unwrap data encryption key", e);
        }
    }

    @Override
    public String activeKeyVersion() {
        return "env-v1";
    }

    @Override
    public void destroy(UUID userId, String externalKeyRef) {
        // Local mode removes the wrapped DEK from the primary database; backups need separate key retention.
    }
}
