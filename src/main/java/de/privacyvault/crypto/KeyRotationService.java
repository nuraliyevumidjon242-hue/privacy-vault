package de.privacyvault.crypto;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.user.UserKeyRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class KeyRotationService {
    private final UserKeyRepository keys;
    private final KeyProvider provider;
    private final KeyRotationWorker worker;
    private final AuditService audit;

    public KeyRotationService(UserKeyRepository keys, KeyProvider provider,
                              KeyRotationWorker worker, AuditService audit) {
        this.keys = keys;
        this.provider = provider;
        this.worker = worker;
        this.audit = audit;
    }

    public int rotateAll(UUID adminId) {
        if (!(provider instanceof AwsKmsKeyProvider)) {
            throw new ApiException(HttpStatus.CONFLICT, "rotation_unavailable",
                    "Key rotation requires the configured managed KMS provider");
        }
        int page = 0;
        int rotated = 0;
        String activeKeyVersion = provider.activeKeyVersion() + ":";
        while (true) {
            var batch = keys.findAllByDestroyedAtIsNull(PageRequest.of(page, 100, Sort.by("userId")));
            if (batch.isEmpty()) break;
            for (var key : batch.getContent()) {
                if (key.getKekVersion().startsWith(activeKeyVersion)) continue;
                KeyRotationWorker.RotationResult result = worker.rotate(key.getUserId());
                provider.destroy(result.userId(), result.oldKeyRef());
                rotated++;
            }
            page++;
            if (!batch.hasNext()) break;
        }
        audit.record(adminId, "KEY_ROTATION", "USER_KEYS", null, "SUCCESS");
        return rotated;
    }
}
