package de.privacyvault.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface UserKeyRepository extends JpaRepository<UserKeyEntity, UUID> {
    Page<UserKeyEntity> findAllByDestroyedAtIsNull(Pageable pageable);
}
