package de.privacyvault.gdpr;

import de.privacyvault.user.UserDataDtos;
import de.privacyvault.user.UserDataService;
import de.privacyvault.security.AuthDtos;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/me/restriction")
public class ProcessingRestrictionController {
    private final UserDataService userDataService;
    public ProcessingRestrictionController(UserDataService userDataService) {
        this.userDataService = userDataService;
    }

    @PatchMapping
    @Operation(summary = "Restrict or resume processing (GDPR Article 18)")
    public AuthDtos.MessageResponse update(@AuthenticationPrincipal UUID userId,
                                           @Valid @RequestBody UserDataDtos.RestrictionRequest request) {
        userDataService.restrict(userId, request.restricted());
        return new AuthDtos.MessageResponse(
                request.restricted() ? "Processing restricted" : "Processing resumed");
    }
}
