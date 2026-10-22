package de.privacyvault.crypto;

import de.privacyvault.config.PrivacyVaultProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {
    private EncryptionService encryption;
    private byte[] dek;

    @BeforeEach
    void setUp() {
        String master = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        String blind = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        String pseudonym = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        var properties = new PrivacyVaultProperties(
                new PrivacyVaultProperties.Crypto(master, blind, pseudonym, "env", "eu-central-1", "v1"),
                new PrivacyVaultProperties.Jwt(master, "test", Duration.ofMinutes(15), Duration.ofDays(7)),
                new PrivacyVaultProperties.Gdpr(14, 365, 730, 1095, 365),
                new PrivacyVaultProperties.Cors(List.of("http://localhost")));
        encryption = new EncryptionService(new EnvKeyProvider(master), properties);
        dek = encryption.generateDek();
    }

    @Test
    void encryptsAndDecryptsWithPerUserKey() {
        UUID userId = UUID.randomUUID();
        byte[] envelope = encryption.encrypt(userId, "first_name", "Ada", dek);
        assertEquals("Ada", encryption.decrypt(userId, "first_name", envelope, dek));
    }

    @Test
    void rejectsTamperedCiphertextAndDifferentAad() {
        UUID userId = UUID.randomUUID();
        byte[] envelope = encryption.encrypt(userId, "email", "private@example.test", dek);
        envelope[envelope.length - 1] ^= 0x01;
        assertThrows(CryptoOperationException.class,
                () -> encryption.decrypt(userId, "email", envelope, dek));

        byte[] valid = encryption.encrypt(userId, "email", "private@example.test", dek);
        assertThrows(CryptoOperationException.class,
                () -> encryption.decrypt(userId, "first_name", valid, dek));
    }

    @Test
    void usesFreshIvForEveryEncryption() {
        UUID userId = UUID.randomUUID();
        byte[] first = encryption.encrypt(userId, "phone", "1234567", dek);
        byte[] second = encryption.encrypt(userId, "phone", "1234567", dek);
        assertFalse(java.util.Arrays.equals(
                java.util.Arrays.copyOfRange(first, 3, 15),
                java.util.Arrays.copyOfRange(second, 3, 15)));
    }

    @Test
    void bindsWrappedDekToUserIdentity() {
        UUID owner = UUID.randomUUID();
        var wrapped = encryption.wrapDek(owner, dek);
        assertArrayEquals(dek, encryption.unwrapDek(owner, wrapped.ciphertext(),
                wrapped.externalKeyRef(), wrapped.version()));
        assertThrows(CryptoOperationException.class, () -> encryption.unwrapDek(
                UUID.randomUUID(), wrapped.ciphertext(), wrapped.externalKeyRef(), wrapped.version()));
    }

    @Test
    void blindIndexIsDeterministicAndNotPlaintext() {
        byte[] one = encryption.blindIndex("user@example.test");
        byte[] two = encryption.blindIndex("user@example.test");
        assertArrayEquals(one, two);
        assertEquals(32, one.length);
        assertNotEquals("user@example.test", java.util.HexFormat.of().formatHex(one));
    }

    @Test
    void separatesEmailIndexesFromPurposeSpecificPseudonyms() {
        String subject = UUID.randomUUID().toString();
        assertFalse(java.util.Arrays.equals(
                encryption.blindIndex(subject),
                encryption.pseudonym("consent-subject", subject)));
        assertFalse(java.util.Arrays.equals(
                encryption.pseudonym("consent-subject", subject),
                encryption.pseudonym("erasure-proof", subject)));
    }
}
