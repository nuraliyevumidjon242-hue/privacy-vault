package de.privacyvault;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import de.privacyvault.crypto.EncryptionService;
import de.privacyvault.security.RefreshTokenRepository;
import de.privacyvault.user.UserKeyRepository;
import de.privacyvault.user.UserProfileRepository;
import de.privacyvault.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataAccessException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
class IntegrationFlowTest {
    private static final String MASTER = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    private static final String BLIND = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    private static final String PSEUDONYM = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    private static final String JWT = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16.6")
            .withDatabaseName("privacyvault")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("privacyvault.crypto.master-key", () -> MASTER);
        registry.add("privacyvault.crypto.blind-index-key", () -> BLIND);
        registry.add("privacyvault.crypto.pseudonym-key", () -> PSEUDONYM);
        registry.add("privacyvault.jwt.secret", () -> JWT);
        registry.add("privacyvault.cors.allowed-origins", () -> "http://localhost:3000");
        registry.add("privacyvault.gdpr.erasure-grace-days", () -> "14");
        registry.add("privacyvault.gdpr.audit-retention-days", () -> "365");
        registry.add("privacyvault.gdpr.inactive-account-days", () -> "730");
        registry.add("privacyvault.gdpr.consent-retention-days", () -> "1095");
        registry.add("privacyvault.gdpr.erasure-proof-retention-days", () -> "365");
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired UserProfileRepository profiles;
    @Autowired UserKeyRepository keys;
    @Autowired RefreshTokenRepository refreshTokens;
    @Autowired EncryptionService encryption;
    @Autowired JdbcTemplate jdbc;

    @Test
    void registerLoginAccessExportAndRectify() throws Exception {
        String email = uniqueEmail();
        JsonNode registered = register(email);
        String access = registered.get("accessToken").asText();
        String password = "Portfolio-Test-Password-21!";

        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(access)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
        mvc.perform(patch("/api/v1/users/me").header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Ada","lastName":"Lovelace","phone":"+49 123 456789","address":"Berlin","dateOfBirth":"1815-12-10"}
                                """))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/users/me/export").header("Authorization", bearer(access)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Ada"))
                .andExpect(jsonPath("$.processingPurposes").isArray());

        var user = users.findByEmailBlindIndex(encryption.blindIndex(email)).orElseThrow();
        String encryptedEmail = new String(user.getEmailEncrypted(), StandardCharsets.ISO_8859_1);
        String encryptedPhone = new String(profiles.findById(user.getId()).orElseThrow().getPhone(),
                StandardCharsets.ISO_8859_1);
        assertFalse(encryptedEmail.contains(email));
        assertFalse(encryptedPhone.contains("+49 123 456789"));

        JsonNode loggedIn = login(email, password);
        assertTrue(loggedIn.hasNonNull("refreshToken"));
    }

    @Test
    void immediateErasureRemovesPersonalRowsAndInvalidatesTokens() throws Exception {
        String email = uniqueEmail();
        String password = "Erase-This-Account-Password-21!";
        JsonNode tokens = register(email, password);
        String access = tokens.get("accessToken").asText();
        String refresh = tokens.get("refreshToken").asText();
        UUID userId = users.findByEmailBlindIndex(encryption.blindIndex(email)).orElseThrow().getId();

        mvc.perform(delete("/api/v1/users/me?immediate=true")
                        .header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(java.util.Map.of("password", password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"));

        assertFalse(users.existsById(userId));
        assertFalse(profiles.existsById(userId));
        assertFalse(keys.existsById(userId));
        assertEquals(0, refreshTokens.findByUserIdAndRevokedAtIsNull(userId).size());
        assertEquals(1, jdbc.queryForObject("select count(*) from erasure_records", Integer.class));
        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(access)))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(java.util.Map.of("refreshToken", refresh))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshReuseRevokesTheWholeTokenFamily() throws Exception {
        String email = uniqueEmail();
        JsonNode initial = register(email);
        String oldAccess = initial.get("accessToken").asText();
        String refresh = initial.get("refreshToken").asText();
        String rotated = refresh(refresh).get("refreshToken").asText();

        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(java.util.Map.of("refreshToken", refresh))))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(java.util.Map.of("refreshToken", rotated))))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(oldAccess)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cancellationTokenRestoresAnAccountAfterPendingErasure() throws Exception {
        String email = uniqueEmail();
        String password = "Cancel-Erasure-Password-21!";
        JsonNode tokens = register(email, password);
        String access = tokens.get("accessToken").asText();
        String response = mvc.perform(delete("/api/v1/users/me")
                        .header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(java.util.Map.of("password", password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn().getResponse().getContentAsString();
        String cancellationToken = mapper.readTree(response).get("cancellationToken").asText();

        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(access)))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/users/me/erasure/cancel").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(
                                java.util.Map.of("cancellationToken", cancellationToken))))
                .andExpect(status().isNoContent());
        String newAccess = login(email, password).get("accessToken").asText();
        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(newAccess)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void consentIsAppendOnlyAndRestrictionBlocksProfileChanges() throws Exception {
        String email = uniqueEmail();
        String access = register(email).get("accessToken").asText();
        mvc.perform(post("/api/v1/users/me/consents").header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"purpose":"product-updates","policyVersion":"2026-01","action":"GRANTED"}
                                """))
                .andExpect(status().isOk());
        mvc.perform(patch("/api/v1/users/me/restriction").header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"restricted\":true}"))
                .andExpect(status().isOk());
        mvc.perform(patch("/api/v1/users/me").header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"firstName\":\"New\"}"))
                .andExpect(status().isConflict());
        mvc.perform(post("/api/v1/users/me/consents").header("Authorization", bearer(access))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"purpose":"product-updates","policyVersion":"2026-01","action":"WITHDRAWN"}
                                """))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/users/me/consents").header("Authorization", bearer(access)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].action").value("WITHDRAWN"));
        mvc.perform(get("/api/v1/users/me/data").header("Authorization", bearer(access)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.processingPurposes").isNotEmpty())
                .andExpect(jsonPath("$.consentHistory.length()").value(2));

        UUID consentId = jdbc.queryForObject("select id from consents limit 1", UUID.class);
        UUID auditId = jdbc.queryForObject("select id from audit_log limit 1", UUID.class);
        assertThrows(DataAccessException.class,
                () -> jdbc.update("update consents set action='GRANTED' where id=?", consentId));
        assertThrows(DataAccessException.class,
                () -> jdbc.update("update audit_log set result='TAMPERED' where id=?", auditId));
    }

    @Test
    void protectedEndpointsRejectAnonymousRequests() throws Exception {
        mvc.perform(get("/api/v1/users/me/data")).andExpect(status().isUnauthorized());
    }

    @Test
    void regularUserIsForbiddenFromAdminAudit() throws Exception {
        String access = register(uniqueEmail()).get("accessToken").asText();
        mvc.perform(get("/api/v1/admin/audit").header("Authorization", bearer(access)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
    }

    @Test
    void adminCanSeeAuditButHasNoPersonalDataReadRoute() throws Exception {
        String adminEmail = uniqueEmail();
        String password = "Portfolio-Test-Password-21!";
        register(adminEmail, password);
        var admin = users.findByEmailBlindIndex(encryption.blindIndex(adminEmail)).orElseThrow();
        jdbc.update("update users set role='ADMIN' where id=?", admin.getId());
        String adminAccess = login(adminEmail, password).get("accessToken").asText();

        mvc.perform(get("/api/v1/admin/audit").header("Authorization", bearer(adminAccess)))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/admin/users/" + UUID.randomUUID() + "/data")
                        .header("Authorization", bearer(adminAccess)))
                .andExpect(status().isNotFound());
    }

    @Test
    void authenticationRateLimitReturns429() throws Exception {
        String ip = "192.0.2.177";
        String invalidBody = mapper.writeValueAsString(java.util.Map.of(
                "email", "missing@example.test", "password", "Incorrect-Password-21!"));
        for (int i = 0; i < 10; i++) {
            mvc.perform(post("/api/v1/auth/login").with(request -> {
                        request.setRemoteAddr(ip);
                        return request;
                    }).contentType(MediaType.APPLICATION_JSON).content(invalidBody))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login").with(request -> {
                    request.setRemoteAddr(ip);
                    return request;
                }).contentType(MediaType.APPLICATION_JSON).content(invalidBody))
                .andExpect(status().isTooManyRequests());
    }

    private JsonNode register(String email) throws Exception {
        return register(email, "Portfolio-Test-Password-21!");
    }

    private JsonNode register(String email, String password) throws Exception {
        String body = mapper.writeValueAsString(java.util.Map.of("email", email, "password", password));
        String response = mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(response);
    }

    private JsonNode login(String email, String password) throws Exception {
        String response = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(java.util.Map.of("email", email, "password", password))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(response);
    }

    private JsonNode refresh(String token) throws Exception {
        String response = mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(java.util.Map.of("refreshToken", token))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(response);
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.test";
    }

    private static String bearer(String token) { return "Bearer " + token; }
}
