package de.privacyvault.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_keys")
public class UserKeyEntity {
    @Id
    @Column(name = "user_id")
    private UUID userId;
    @Column(name = "wrapped_dek", nullable = false, columnDefinition = "bytea")
    private byte[] wrappedDek;
    @Column(name = "external_key_ref", nullable = false)
    private String externalKeyRef;
    @Column(name = "kek_version", nullable = false)
    private String kekVersion;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "destroyed_at")
    private Instant destroyedAt;

    protected UserKeyEntity() {}
    public UserKeyEntity(UUID userId, byte[] wrappedDek, String externalKeyRef, String kekVersion, Instant now) {
        this.userId = userId;
        this.wrappedDek = wrappedDek;
        this.externalKeyRef = externalKeyRef;
        this.kekVersion = kekVersion;
        this.createdAt = now;
    }
    public UUID getUserId() { return userId; }
    public byte[] getWrappedDek() { return wrappedDek; }
    public String getExternalKeyRef() { return externalKeyRef; }
    public String getKekVersion() { return kekVersion; }
    public Instant getDestroyedAt() { return destroyedAt; }
    public void markDestroyed(Instant now) { destroyedAt = now; wrappedDek = new byte[0]; }
    public void replaceWrappedDek(byte[] wrappedDek, String externalKeyRef, String version) {
        this.wrappedDek = wrappedDek;
        this.externalKeyRef = externalKeyRef;
        this.kekVersion = version;
    }
}
