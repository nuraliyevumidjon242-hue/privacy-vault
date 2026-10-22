package de.privacyvault.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_log")
public class AuditLogEntity {
    @Id private UUID id;
    @Column(name = "actor_ref", nullable = false) private String actorRef;
    @Column(nullable = false) private String action;
    @Column(name = "resource_type", nullable = false) private String resourceType;
    @Column(name = "resource_ref") private String resourceRef;
    @Column(nullable = false) private String result;
    @Column(name = "request_id", nullable = false) private String requestId;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;

    protected AuditLogEntity() {}
    public AuditLogEntity(String actorRef, String action, String resourceType, String resourceRef,
                          String result, String requestId, Instant now) {
        this.id = UUID.randomUUID();
        this.actorRef = actorRef;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceRef = resourceRef;
        this.result = result;
        this.requestId = requestId;
        this.occurredAt = now;
    }
    public UUID getId() { return id; }
    public String getActorRef() { return actorRef; }
    public String getAction() { return action; }
    public String getResourceType() { return resourceType; }
    public String getResourceRef() { return resourceRef; }
    public String getResult() { return result; }
    public String getRequestId() { return requestId; }
    public Instant getOccurredAt() { return occurredAt; }
}
