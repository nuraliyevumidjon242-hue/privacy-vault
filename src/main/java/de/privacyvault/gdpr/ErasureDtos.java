package de.privacyvault.gdpr;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class ErasureDtos {
    private ErasureDtos() {}
    public record Request(@NotBlank String password) {}
    public record Cancellation(@NotBlank @Size(max = 64) String cancellationToken) {}
    public record Response(String status, Instant scheduledFor, String cancellationToken) {}
}
