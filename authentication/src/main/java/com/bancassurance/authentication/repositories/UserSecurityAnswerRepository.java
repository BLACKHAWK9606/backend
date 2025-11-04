package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.UserSecurityAnswer;
import com.bancassurance.authentication.models.SecurityQuestion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSecurityAnswerRepository extends JpaRepository<UserSecurityAnswer, Long> {
    
    List<UserSecurityAnswer> findByUserUserId(Long userId);
    
    boolean existsByUserUserIdAndQuestionQuestionId(Long userId, Long questionId);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM UserSecurityAnswer usa WHERE usa.user.userId = :userId")
    void deleteByUserUserId(@Param("userId") Long userId);
    
    @Query("SELECT usa.answerHash FROM UserSecurityAnswer usa WHERE usa.user.userId = :userId AND usa.question.questionId = :questionId")
    Optional<String> findAnswerHashByUserIdAndQuestionId(@Param("userId") Long userId, @Param("questionId") Long questionId);
    
    @Query("SELECT usa.question FROM UserSecurityAnswer usa WHERE usa.user.userId = :userId")
    List<SecurityQuestion> findSecurityQuestionsByUserId(@Param("userId") Long userId);
    
    @Query("SELECT COUNT(usa) FROM UserSecurityAnswer usa WHERE usa.user.userId = :userId")
    long countByUserId(@Param("userId") Long userId);
}