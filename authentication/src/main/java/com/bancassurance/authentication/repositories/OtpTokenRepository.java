package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.OtpToken;
import com.bancassurance.authentication.models.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {
    
    Optional<OtpToken> findByUserUserIdAndPurposeAndIsVerifiedFalseAndIsExpiredFalse(Long userId, OtpPurpose purpose);
    
    Optional<OtpToken> findByPhoneNumberAndPurposeAndIsVerifiedFalseAndIsExpiredFalse(String phoneNumber, OtpPurpose purpose);
    
    List<OtpToken> findByUserUserIdAndPurpose(Long userId, OtpPurpose purpose);
    
    @Modifying
    @Query("UPDATE OtpToken o SET o.isExpired = true WHERE o.expiresAt < :currentTime AND o.isExpired = false")
    int expireOldTokens(@Param("currentTime") LocalDateTime currentTime);
    
    @Modifying
    @Query("DELETE FROM OtpToken o WHERE o.createdAt < :cutoffTime")
    int deleteOldTokens(@Param("cutoffTime") LocalDateTime cutoffTime);
    
    @Modifying
    @Query("UPDATE OtpToken o SET o.isExpired = true WHERE o.user.userId = :userId AND o.purpose = :purpose AND o.isExpired = false")
    int expireUserTokensForPurpose(@Param("userId") Long userId, @Param("purpose") OtpPurpose purpose);
}