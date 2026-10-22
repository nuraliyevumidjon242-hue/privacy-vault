package de.privacyvault.security;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class AuthDtos {
    private AuthDtos() {}
    public record RegisterRequest(@NotBlank @Email @Size(max = 254) String email,
                                  @NotBlank @Size(min = 12, max = 128) String password) {}
    public record LoginRequest(@NotBlank @Email @Size(max = 254) String email,
                               @NotBlank @Size(max = 128) String password) {}
    public record RefreshRequest(@NotBlank @Size(max = 128) String refreshToken) {}
    public record LogoutRequest(@NotBlank @Size(max = 128) String refreshToken) {}
    public record TokenResponse(String accessToken, String refreshToken,
                                Instant accessExpiresAt, Instant refreshExpiresAt) {}
    public record MessageResponse(String message) {}
}
