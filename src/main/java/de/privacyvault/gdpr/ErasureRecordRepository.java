package de.privacyvault.gdpr;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.UUID;

public interface ErasureRecordRepository extends JpaRepository<ErasureRecordEntity, UUID> {
    @Modifying
    @Query("delete from ErasureRecordEntity r where r.erasedAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
