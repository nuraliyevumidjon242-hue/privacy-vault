package de.privacyvault.crypto;

import de.privacyvault.config.PrivacyVaultProperties;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class EncryptionService {
    private static final byte FORMAT_VERSION = 1;
    private static final byte[] CRYPTO_VERSION = new byte[]{0, 1};
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private final KeyProvider keyProvider;
    private final byte[] blindIndexKey;
    private final byte[] pseudonymKey;
    private final SecureRandom random = new SecureRandom();

    public EncryptionService(KeyProvider keyProvider, PrivacyVaultProperties properties) {
        this.keyProvider = keyProvider;
        this.blindIndexKey = HexFormat.of().parseHex(properties.crypto().blindIndexKey());
        this.pseudonymKey = HexFormat.of().parseHex(properties.crypto().pseudonymKey());
        if (blindIndexKey.length < 32) throw new IllegalStateException("Blind-index key must contain at least 32 bytes");
        if (pseudonymKey.length < 32) throw new IllegalStateException("Pseudonym key must contain at least 32 bytes");
    }

    public byte[] generateDek() {
        byte[] key = new byte[32];
        random.nextBytes(key);
        return key;
    }

    public KeyProvider.WrappedKey wrapDek(UUID userId, byte[] dek) {
        return keyProvider.wrap(userId, dek);
    }

    public byte[] unwrapDek(UUID userId, byte[] wrapped, String externalRef, String version) {
        return keyProvider.unwrap(userId, new KeyProvider.WrappedKey(wrapped, externalRef, version));
    }

    public byte[] encrypt(UUID userId, String field, String plaintext, byte[] dek) {
        if (plaintext == null) return null;
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(userId, field));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.allocate(1 + CRYPTO_VERSION.length + IV_LENGTH + encrypted.length)
                    .put(FORMAT_VERSION).put(CRYPTO_VERSION).put(iv).put(encrypted).array();
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Unable to encrypt personal data", e);
        }
    }

    public String decrypt(UUID userId, String field, byte[] envelope, byte[] dek) {
        if (envelope == null) return null;
        if (envelope.length < 1 + CRYPTO_VERSION.length + IV_LENGTH + 16 || envelope[0] != FORMAT_VERSION
                || envelope[1] != CRYPTO_VERSION[0] || envelope[2] != CRYPTO_VERSION[1]) {
            throw new CryptoOperationException("Encrypted value has an unsupported format");
        }
        byte[] iv = Arrays.copyOfRange(envelope, 3, 3 + IV_LENGTH);
        byte[] encrypted = Arrays.copyOfRange(envelope, 3 + IV_LENGTH, envelope.length);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(userId, field));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Encrypted value authentication failed", e);
        }
    }

    public byte[] blindIndex(String normalizedEmail) {
        return hmac(blindIndexKey, "email-index", normalizedEmail);
    }

    public byte[] pseudonym(String purpose, String value) {
        if (purpose == null || !purpose.matches("[a-z-]{1,40}")) {
            throw new IllegalArgumentException("Pseudonym purpose must be a lowercase identifier");
        }
        return hmac(pseudonymKey, purpose, value);
    }

    private static byte[] hmac(byte[] key, String purpose, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(purpose.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0);
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new CryptoOperationException("Unable to calculate email lookup index", e);
        }
    }

    private static byte[] aad(UUID userId, String field) {
        return (userId + ":" + field).getBytes(StandardCharsets.UTF_8);
    }
}
