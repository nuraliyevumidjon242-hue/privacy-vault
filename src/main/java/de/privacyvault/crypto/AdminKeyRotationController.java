package de.privacyvault.crypto;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/keys")
public class AdminKeyRotationController {
    private final KeyRotationService service;
    public AdminKeyRotationController(KeyRotationService service) { this.service = service; }

    @PostMapping("/rotate")
    @Operation(summary = "Re-wrap user DEKs with new per-user KMS keys")
    public Map<String, Integer> rotate(@AuthenticationPrincipal UUID adminId) {
        return Map.of("rotatedKeys", service.rotateAll(adminId));
    }
}
