package de.privacyvault.user;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.List;

public final class UserDataDtos {
    private UserDataDtos() {}

    public record PatchProfileRequest(
            @Size(max = 100) String firstName,
            @Size(max = 100) String lastName,
            @Pattern(regexp = "^$|^[+0-9 ()-]{7,30}$") String phone,
            @Size(max = 500) String address,
            @Pattern(regexp = "^$|^\\d{4}-\\d{2}-\\d{2}$") String dateOfBirth) {}
    public record UserDataResponse(String email, String firstName, String lastName, String phone,
                                   String address, String dateOfBirth, String status,
                                   List<String> processingPurposes, List<ConsentData> consentHistory,
                                   String retentionInformation, Instant accountCreatedAt) {}
    public record ConsentData(String purpose, String policyVersion, String action, Instant recordedAt) {}
    public record ErasureRequestResponse(String status, Instant scheduledFor) {}
    public record RestrictionRequest(@NotNull Boolean restricted) {}
}
