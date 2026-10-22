package de.privacyvault.gdpr;

import de.privacyvault.security.AuthDtos;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/me")
public class ErasureController {
    private final ErasureService service;
    public ErasureController(ErasureService service) { this.service = service; }

    @DeleteMapping
    @Operation(summary = "Request account erasure; immediate=true skips the grace period (GDPR Article 17)")
    public ErasureDtos.Response request(@AuthenticationPrincipal UUID userId,
                                        @Valid @RequestBody ErasureDtos.Request request,
                                        @RequestParam(defaultValue = "false") boolean immediate) {
        ErasureDtos.Response response = service.request(userId, request, immediate);
        if (immediate) {
            service.completeImmediately(userId);
            return new ErasureDtos.Response("COMPLETED", response.scheduledFor(), null);
        }
        return response;
    }

    @PostMapping("/erasure/cancel")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Cancel a pending erasure using the one-time cancellation token")
    public void cancel(@Valid @RequestBody ErasureDtos.Cancellation request) {
        service.cancel(request);
    }
}
