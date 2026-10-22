package de.privacyvault.audit;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/audit")
public class AdminAuditController {
    private final AuditLogRepository audit;
    public AdminAuditController(AuditLogRepository audit) { this.audit = audit; }

    @GetMapping
    @Operation(summary = "Read audit metadata; never returns decrypted personal data")
    public Page<AuditEntry> list(@RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "50") int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(100, Math.max(1, size));
        return audit.findAll(PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "occurredAt")))
                .map(entry -> new AuditEntry(entry.getActorRef(), entry.getAction(),
                        entry.getResourceType(), entry.getResourceRef(), entry.getResult(),
                        entry.getRequestId(), entry.getOccurredAt()));
    }

    public record AuditEntry(String actorRef, String action, String resourceType,
                             String resourceRef, String result, String requestId, Instant occurredAt) {}
}
