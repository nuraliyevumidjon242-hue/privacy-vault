package de.privacyvault.gdpr;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ErasureRequestRepository extends JpaRepository<ErasureRequestEntity, UUID> {
    Optional<ErasureRequestEntity> findFirstByUserIdAndStatusOrderByRequestedAtDesc(UUID userId, String status);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from ErasureRequestEntity r where r.cancelTokenHash = :tokenHash and r.status = :status")
    Optional<ErasureRequestEntity> findLockedByCancelTokenHashAndStatus(
            @Param("tokenHash") byte[] cancelTokenHash, @Param("status") String status);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from ErasureRequestEntity r where r.status = :status and r.scheduledFor <= :now")
    List<ErasureRequestEntity> findDueForUpdate(@Param("status") String status, @Param("now") Instant now);
}
