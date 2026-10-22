package de.privacyvault.consent;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class ConsentDtos {
    private ConsentDtos() {}
    public record ConsentRequest(@NotBlank @Size(max = 100) String purpose,
                                 @NotBlank @Size(max = 64) String policyVersion,
                                 @NotBlank @Pattern(regexp = "GRANTED|WITHDRAWN") String action) {}
    public record ConsentResponse(String purpose, String policyVersion, String action, Instant recordedAt) {}
}
