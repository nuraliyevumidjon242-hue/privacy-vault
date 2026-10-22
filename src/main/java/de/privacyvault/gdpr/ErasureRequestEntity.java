package de.privacyvault.gdpr;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "erasure_requests")
public class ErasureRequestEntity {
    @Id private UUID id;
    @Column(name = "user_id", nullable = false) private UUID userId;
    @Column(name = "requested_at", nullable = false) private Instant requestedAt;
    @Column(name = "scheduled_for", nullable = false) private Instant scheduledFor;
    @Column(name = "previous_status", nullable = false) private String previousStatus;
    @Column(name = "cancel_token_hash", columnDefinition = "bytea") private byte[] cancelTokenHash;
    @Column(name = "cancelled_at") private Instant cancelledAt;
    @Column(name = "completed_at") private Instant completedAt;
    @Column(nullable = false) private String status;

    protected ErasureRequestEntity() {}
    public ErasureRequestEntity(UUID userId, Instant requestedAt, Instant scheduledFor,
                                String previousStatus, byte[] cancelTokenHash) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.requestedAt = requestedAt;
        this.scheduledFor = scheduledFor;
        this.previousStatus = previousStatus;
        this.cancelTokenHash = cancelTokenHash;
        this.status = "PENDING";
    }
    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public Instant getScheduledFor() { return scheduledFor; }
    public String getStatus() { return status; }
    public String getPreviousStatus() { return previousStatus; }
    public byte[] getCancelTokenHash() { return cancelTokenHash; }
    public void cancel(Instant now) { this.status = "CANCELLED"; this.cancelledAt = now; this.cancelTokenHash = null; }
    public void complete(Instant now) { this.status = "COMPLETED"; this.completedAt = now; }
}
