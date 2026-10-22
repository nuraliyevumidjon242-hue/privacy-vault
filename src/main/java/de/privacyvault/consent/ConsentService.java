package de.privacyvault.consent;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.user.UserEntity;
import de.privacyvault.user.UserRepository;
import de.privacyvault.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class ConsentService {
    private final ConsentRepository consents;
    private final UserRepository users;
    private final EncryptionService encryption;
    private final HttpServletRequest request;
    private final AuditService audit;

    public ConsentService(ConsentRepository consents, UserRepository users, EncryptionService encryption,
                         HttpServletRequest request, AuditService audit) {
        this.consents = consents;
        this.users = users;
        this.encryption = encryption;
        this.request = request;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<ConsentDtos.ConsentResponse> history(UUID userId) {
        byte[] subject = encryption.pseudonym("consent-subject", userId.toString());
        return consents.findBySubjectRefOrderByEventSequenceDesc(subject).stream()
                .map(c -> new ConsentDtos.ConsentResponse(c.getPurpose(), c.getPolicyVersion(),
                        c.getAction(), c.getRecordedAt())).toList();
    }

    @Transactional
    public ConsentDtos.ConsentResponse record(UUID userId, ConsentDtos.ConsentRequest input) {
        UserEntity user = users.findById(userId).orElseThrow(ApiException::notFound);
        if (!"WITHDRAWN".equals(input.action()) && user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(HttpStatus.CONFLICT, "processing_restricted",
                    "Consent cannot be granted while processing is restricted");
        }
        String ipAddress = request.getRemoteAddr();
        byte[] ipHash = ipAddress == null ? null : encryption.pseudonym("consent-ip", ipAddress);
        Instant now = Instant.now();
        ConsentEntity entity = consents.save(new ConsentEntity(encryption.pseudonym("consent-subject", userId.toString()),
                input.purpose().trim(), input.policyVersion().trim(), input.action(), ipHash, now));
        audit.record(userId, "CONSENT_" + input.action(), "CONSENT", entity.getId(), "SUCCESS");
        return new ConsentDtos.ConsentResponse(entity.getPurpose(), entity.getPolicyVersion(),
                entity.getAction(), entity.getRecordedAt());
    }
}
