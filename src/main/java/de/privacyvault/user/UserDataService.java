package de.privacyvault.user;

import de.privacyvault.audit.AuditService;
import de.privacyvault.common.ApiException;
import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.consent.ConsentRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class UserDataService {
    private final UserRepository users;
    private final UserProfileRepository profiles;
    private final UserKeyRepository keys;
    private final ConsentRepository consents;
    private final EncryptionService encryption;
    private final AuditService audit;

    public UserDataService(UserRepository users, UserProfileRepository profiles, UserKeyRepository keys,
                           ConsentRepository consents,
                           EncryptionService encryption, AuditService audit) {
        this.users = users;
        this.profiles = profiles;
        this.keys = keys;
        this.consents = consents;
        this.encryption = encryption;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public UserDataDtos.UserDataResponse getData(UUID userId, boolean exported) {
        UserEntity user = requireUser(userId);
        ensureReadable(user);
        UserProfileEntity profile = profiles.findById(userId).orElseThrow(ApiException::notFound);
        byte[] dek = getDek(userId);
        try {
            var consentHistory = consents.findBySubjectRefOrderByEventSequenceDesc(
                            encryption.pseudonym("consent-subject", userId.toString())).stream()
                    .map(c -> new UserDataDtos.ConsentData(c.getPurpose(), c.getPolicyVersion(),
                            c.getAction(), c.getRecordedAt())).toList();
            java.util.Map<String, String> latest = new java.util.LinkedHashMap<>();
            consentHistory.forEach(c -> latest.putIfAbsent(c.purpose(), c.action()));
            java.util.LinkedHashSet<String> purposes = latest.entrySet().stream()
                    .filter(entry -> "GRANTED".equals(entry.getValue()))
                    .map(java.util.Map.Entry::getKey)
                    .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
            purposes.addAll(List.of("account-management", "authentication",
                    "security-and-abuse-prevention", "data-subject-rights"));
            audit.record(userId, exported ? "DATA_EXPORT" : "DATA_ACCESS", "USER_DATA", userId, "SUCCESS");
            return new UserDataDtos.UserDataResponse(
                    encryption.decrypt(userId, "email", user.getEmailEncrypted(), dek),
                    encryption.decrypt(userId, "first_name", profile.getFirstName(), dek),
                    encryption.decrypt(userId, "last_name", profile.getLastName(), dek),
                    encryption.decrypt(userId, "phone", profile.getPhone(), dek),
                    encryption.decrypt(userId, "address", profile.getAddress(), dek),
                    encryption.decrypt(userId, "date_of_birth", profile.getDateOfBirth(), dek),
                    user.getStatus().name(), List.copyOf(purposes), consentHistory,
                    "Account data is retained until erasure is completed or a documented legal retention duty applies.",
                    user.getCreatedAt());
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    @Transactional
    public void patch(UUID userId, UserDataDtos.PatchProfileRequest patch) {
        UserEntity user = requireUser(userId);
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ApiException(HttpStatus.CONFLICT, "processing_restricted",
                    "Profile changes are unavailable while processing is restricted");
        }
        UserProfileEntity profile = profiles.findById(userId).orElseThrow(ApiException::notFound);
        if (patch.dateOfBirth() != null && !patch.dateOfBirth().isBlank()) {
            try {
                if (java.time.LocalDate.parse(patch.dateOfBirth()).isAfter(java.time.LocalDate.now())) {
                    throw new IllegalArgumentException();
                }
            } catch (java.time.DateTimeException | IllegalArgumentException exception) {
                throw new ApiException(HttpStatus.BAD_REQUEST, "invalid_date_of_birth",
                        "Date of birth must be a valid date that is not in the future");
            }
        }
        byte[] dek = getDek(userId);
        try {
            profile.update(
                    encryptIfPresent(userId, "first_name", patch.firstName(), profile.getFirstName(), dek),
                    encryptIfPresent(userId, "last_name", patch.lastName(), profile.getLastName(), dek),
                    encryptIfPresent(userId, "phone", patch.phone(), profile.getPhone(), dek),
                    encryptIfPresent(userId, "address", patch.address(), profile.getAddress(), dek),
                    encryptIfPresent(userId, "date_of_birth", patch.dateOfBirth(), profile.getDateOfBirth(), dek),
                    Instant.now());
            profiles.save(profile);
            audit.record(userId, "RECTIFICATION", "USER_PROFILE", userId, "SUCCESS");
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    @Transactional
    public void restrict(UUID userId, boolean restricted) {
        UserEntity user = requireUser(userId);
        if (restricted && user.getStatus() == UserStatus.ACTIVE) user.setStatus(UserStatus.RESTRICTED, Instant.now());
        else if (!restricted && user.getStatus() == UserStatus.RESTRICTED) user.setStatus(UserStatus.ACTIVE, Instant.now());
        else if (user.getStatus() != UserStatus.ACTIVE && user.getStatus() != UserStatus.RESTRICTED) {
            throw new ApiException(HttpStatus.CONFLICT, "invalid_account_state", "Account state does not allow this change");
        }
        audit.record(userId, restricted ? "PROCESSING_RESTRICTED" : "PROCESSING_RESUMED",
                "USER", userId, "SUCCESS");
    }

    private byte[] encryptIfPresent(UUID userId, String field, String value, byte[] current, byte[] dek) {
        return value == null ? current : encryption.encrypt(userId, field, value, dek);
    }

    private byte[] getDek(UUID userId) {
        UserKeyEntity key = keys.findById(userId).orElseThrow(ApiException::notFound);
        if (key.getDestroyedAt() != null || key.getWrappedDek().length == 0) throw ApiException.notFound();
        return encryption.unwrapDek(userId, key.getWrappedDek(), key.getExternalKeyRef(), key.getKekVersion());
    }

    private UserEntity requireUser(UUID id) {
        return users.findById(id).orElseThrow(ApiException::notFound);
    }

    private static void ensureReadable(UserEntity user) {
        if (user.getStatus() == UserStatus.ERASURE_PENDING || user.getStatus() == UserStatus.ERASED) {
            throw ApiException.notFound();
        }
    }
}
