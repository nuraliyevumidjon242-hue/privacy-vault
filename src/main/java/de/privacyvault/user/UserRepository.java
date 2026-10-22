package de.privacyvault.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmailBlindIndex(byte[] emailBlindIndex);
    Page<UserEntity> findAllByStatusAndLastLoginAtBefore(UserStatus status, Instant cutoff, Pageable pageable);
}
