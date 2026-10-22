package de.privacyvault.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_profiles")
public class UserProfileEntity {
    @Id
    @Column(name = "user_id")
    private UUID userId;
    @Column(name = "first_name", columnDefinition = "bytea")
    private byte[] firstName;
    @Column(name = "last_name", columnDefinition = "bytea")
    private byte[] lastName;
    @Column(name = "phone", columnDefinition = "bytea")
    private byte[] phone;
    @Column(name = "address", columnDefinition = "bytea")
    private byte[] address;
    @Column(name = "date_of_birth", columnDefinition = "bytea")
    private byte[] dateOfBirth;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected UserProfileEntity() {}

    public UserProfileEntity(UUID userId, Instant now) {
        this.userId = userId;
        this.updatedAt = now;
    }
    public UUID getUserId() { return userId; }
    public byte[] getFirstName() { return firstName; }
    public byte[] getLastName() { return lastName; }
    public byte[] getPhone() { return phone; }
    public byte[] getAddress() { return address; }
    public byte[] getDateOfBirth() { return dateOfBirth; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void update(byte[] firstName, byte[] lastName, byte[] phone, byte[] address, byte[] dateOfBirth, Instant now) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.phone = phone;
        this.address = address;
        this.dateOfBirth = dateOfBirth;
        this.updatedAt = now;
    }
}
