package de.privacyvault.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    private UUID id;
    @Column(name = "email_encrypted", nullable = false, columnDefinition = "bytea")
    private byte[] emailEncrypted;
    @Column(name = "email_blind_index", nullable = false, unique = true, columnDefinition = "bytea")
    private byte[] emailBlindIndex;
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status;
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;
    @Column(name = "locked_until")
    private Instant lockedUntil;
    @Column(name = "last_login_at")
    private Instant lastLoginAt;
    @Column(name = "token_version", nullable = false)
    private long tokenVersion;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected UserEntity() {}

    public UserEntity(UUID id, byte[] emailEncrypted, byte[] emailBlindIndex, String passwordHash, Instant now) {
        this.id = id;
        this.emailEncrypted = emailEncrypted;
        this.emailBlindIndex = emailBlindIndex;
        this.passwordHash = passwordHash;
        this.role = Role.USER;
        this.status = UserStatus.ACTIVE;
        this.createdAt = now;
        this.updatedAt = now;
        this.lastLoginAt = now;
    }

    public UUID getId() { return id; }
    public byte[] getEmailEncrypted() { return emailEncrypted; }
    public byte[] getEmailBlindIndex() { return emailBlindIndex; }
    public String getPasswordHash() { return passwordHash; }
    public Role getRole() { return role; }
    public UserStatus getStatus() { return status; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public Instant getLockedUntil() { return lockedUntil; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public long getTokenVersion() { return tokenVersion; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void failedLogin(Instant now, boolean lock) {
        failedLoginAttempts++;
        if (lock) {
            status = UserStatus.LOCKED;
            lockedUntil = now.plusSeconds(900);
        }
        updatedAt = now;
    }
    public void successfulLogin(Instant now) {
        failedLoginAttempts = 0;
        lockedUntil = null;
        if (status == UserStatus.LOCKED || status == UserStatus.INACTIVE) status = UserStatus.ACTIVE;
        updatedAt = now;
        lastLoginAt = now;
    }
    public void markInactive(Instant now) {
        if (status == UserStatus.ACTIVE) {
            status = UserStatus.INACTIVE;
            tokenVersion++;
            updatedAt = now;
        }
    }
    public void setStatus(UserStatus status, Instant now) { this.status = status; this.updatedAt = now; }
    public void incrementTokenVersion(Instant now) { tokenVersion++; updatedAt = now; }
    public void setPasswordHash(String hash) { passwordHash = hash; }
}
