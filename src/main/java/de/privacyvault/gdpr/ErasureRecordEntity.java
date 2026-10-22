package de.privacyvault.gdpr;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "erasure_records")
public class ErasureRecordEntity {
    @Id private UUID id;
    @Column(name = "subject_hash", nullable = false, columnDefinition = "bytea") private byte[] subjectHash;
    @Column(name = "erased_at", nullable = false) private Instant erasedAt;

    protected ErasureRecordEntity() {}
    public ErasureRecordEntity(byte[] subjectHash, Instant erasedAt) {
        this.id = UUID.randomUUID();
        this.subjectHash = subjectHash;
        this.erasedAt = erasedAt;
    }
}
