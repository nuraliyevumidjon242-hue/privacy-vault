package de.privacyvault.consent;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "consents")
public class ConsentEntity {
    @Id private UUID id;
    @Column(name = "event_sequence", insertable = false, updatable = false)
    private Long eventSequence;
    @Column(name = "subject_ref", nullable = false, columnDefinition = "bytea") private byte[] subjectRef;
    @Column(nullable = false) private String purpose;
    @Column(name = "policy_version", nullable = false) private String policyVersion;
    @Column(nullable = false) private String action;
    @Column(name = "ip_hash", columnDefinition = "bytea") private byte[] ipHash;
    @Column(name = "recorded_at", nullable = false) private Instant recordedAt;

    protected ConsentEntity() {}
    public ConsentEntity(byte[] subjectRef, String purpose, String policyVersion,
                         String action, byte[] ipHash, Instant now) {
        this.id = UUID.randomUUID();
        this.subjectRef = subjectRef;
        this.purpose = purpose;
        this.policyVersion = policyVersion;
        this.action = action;
        this.ipHash = ipHash;
        this.recordedAt = now;
    }
    public UUID getId() { return id; }
    public byte[] getSubjectRef() { return subjectRef; }
    public String getPurpose() { return purpose; }
    public String getPolicyVersion() { return policyVersion; }
    public String getAction() { return action; }
    public Instant getRecordedAt() { return recordedAt; }
}
