package de.privacyvault.audit;

import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.common.RequestIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

@Service
public class AuditService {
    private final AuditLogRepository repository;
    private final EncryptionService encryptionService;
    private final HttpServletRequest request;

    public AuditService(AuditLogRepository repository, EncryptionService encryptionService,
                       HttpServletRequest request) {
        this.repository = repository;
        this.encryptionService = encryptionService;
        this.request = request;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(UUID actor, String action, String resourceType, UUID resourceId, String result) {
        String actorRef = actor == null ? "anonymous" : ref("audit-actor", actor);
        String resourceRef = resourceId == null ? null : ref("audit-resource", resourceId);
        Object requestId = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        repository.save(new AuditLogEntity(actorRef, action, resourceType, resourceRef, result,
                requestId == null ? "unavailable" : requestId.toString(), Instant.now()));
    }

    public String ref(String purpose, UUID id) {
        return java.util.HexFormat.of().formatHex(encryptionService.pseudonym(purpose, id.toString()));
    }
}
