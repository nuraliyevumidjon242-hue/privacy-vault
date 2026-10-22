package de.privacyvault.consent;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ConsentRepository extends JpaRepository<ConsentEntity, UUID> {
    List<ConsentEntity> findBySubjectRefOrderByEventSequenceDesc(byte[] subjectRef);
    @Modifying
    @Query("delete from ConsentEntity c where c.recordedAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
