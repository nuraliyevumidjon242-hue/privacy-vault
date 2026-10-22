package de.privacyvault.consent;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/me/consents")
public class ConsentController {
    private final ConsentService service;
    public ConsentController(ConsentService service) { this.service = service; }

    @GetMapping
    @Operation(summary = "Read append-only consent history")
    public List<ConsentDtos.ConsentResponse> history(@AuthenticationPrincipal UUID userId) {
        return service.history(userId);
    }

    @PostMapping
    @Operation(summary = "Append a consent grant or withdrawal event (GDPR Article 7)")
    public ConsentDtos.ConsentResponse record(@AuthenticationPrincipal UUID userId,
                                              @Valid @RequestBody ConsentDtos.ConsentRequest request) {
        return service.record(userId, request);
    }
}
