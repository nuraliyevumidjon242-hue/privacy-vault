package de.privacyvault.security;

import de.privacyvault.config.PrivacyVaultProperties;
import de.privacyvault.user.Role;
import de.privacyvault.user.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class JwtService {
    private final SecretKey key;
    private final String issuer;
    private final java.time.Duration accessTtl;

    public JwtService(PrivacyVaultProperties properties) {
        byte[] bytes = HexFormat.of().parseHex(properties.jwt().secret());
        if (bytes.length < 32) throw new IllegalStateException("JWT secret must contain at least 32 random bytes");
        key = new SecretKeySpec(bytes, "HmacSHA256");
        issuer = properties.jwt().issuer();
        accessTtl = properties.jwt().accessTtl();
    }

    public String issue(UserEntity user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(issuer)
                .subject(user.getId().toString())
                .claim("role", user.getRole().name())
                .claim("ver", user.getTokenVersion())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTtl)))
                .signWith(key)
                .compact();
    }

    public AccessClaims parse(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(key).requireIssuer(issuer).build()
                    .parseSignedClaims(token).getPayload();
            return new AccessClaims(UUID.fromString(claims.getSubject()),
                    Role.valueOf(claims.get("role", String.class)),
                    claims.get("ver", Number.class).longValue());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidAccessTokenException();
        }
    }

    public record AccessClaims(UUID userId, Role role, long tokenVersion) {}
    public static class InvalidAccessTokenException extends RuntimeException {}
}
