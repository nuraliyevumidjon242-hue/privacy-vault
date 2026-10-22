package de.privacyvault.user;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/me")
public class UserController {
    private final UserDataService service;
    public UserController(UserDataService service) { this.service = service; }

    @GetMapping("/data")
    @Operation(summary = "Access the authenticated user's decrypted personal data (GDPR Article 15)")
    public UserDataDtos.UserDataResponse data(@AuthenticationPrincipal UUID userId) {
        return service.getData(userId, false);
    }

    @GetMapping("/export")
    @Operation(summary = "Export personal data as machine-readable JSON (GDPR Article 20)")
    public UserDataDtos.UserDataResponse export(@AuthenticationPrincipal UUID userId) {
        return service.getData(userId, true);
    }

    @PatchMapping
    @Operation(summary = "Rectify the authenticated user's profile (GDPR Article 16)")
    public AuthMessageResponse patch(@AuthenticationPrincipal UUID userId,
                                     @Valid @RequestBody UserDataDtos.PatchProfileRequest request) {
        service.patch(userId, request);
        return new AuthMessageResponse("Profile updated");
    }

    public record AuthMessageResponse(String message) {}
}
