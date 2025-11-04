package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.SecurityQuestion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface SecurityQuestionRepository extends JpaRepository<SecurityQuestion, Long> {
    
    List<SecurityQuestion> findByIsActiveTrueOrderByQuestionText();
    
    List<SecurityQuestion> findByIsActiveTrue();
}