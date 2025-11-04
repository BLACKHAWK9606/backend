package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.*;
import com.bancassurance.authentication.repositories.*;
import com.bancassurance.authentication.services.AuthService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.annotation.PostConstruct;

import java.util.*;

@Service
public class SecurityQuestionService {
    
    private AuthService authService;
    
    private final SecurityQuestionRepository securityQuestionRepository;
    private final UserSecurityAnswerRepository userSecurityAnswerRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public SecurityQuestionService(SecurityQuestionRepository securityQuestionRepository,
                                 UserSecurityAnswerRepository userSecurityAnswerRepository,
                                 UserRepository userRepository,
                                 PasswordEncoder passwordEncoder) {
        this.securityQuestionRepository = securityQuestionRepository;
        this.userSecurityAnswerRepository = userSecurityAnswerRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Autowired
    public void setAuthService(AuthService authService) {
        this.authService = authService;
        authService.setSecurityQuestionService(this);
    }
    
    public List<SecurityQuestion> getActiveQuestions() {
        return securityQuestionRepository.findByIsActiveTrueOrderByQuestionText();
    }
    
    @Transactional
    public void setUserSecurityAnswers(Long userId, List<SecurityAnswerRequest> answers) {
        if (answers.size() < 3 || answers.size() > 5) {
            throw new RuntimeException("Must provide between 3 and 5 security questions");
        }
        
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        
        User user = userOptional.get();
        
        // Remove existing answers
        userSecurityAnswerRepository.deleteByUserUserId(userId);
        
        // Validate no duplicate questions
        Set<Long> questionIds = new HashSet<>();
        for (SecurityAnswerRequest answer : answers) {
            if (!questionIds.add(answer.getQuestionId())) {
                throw new RuntimeException("Duplicate questions not allowed");
            }
            if (answer.getAnswer().trim().length() < 3) {
                throw new RuntimeException("Each answer must be at least 3 characters");
            }
        }
        
        // Save new answers
        for (SecurityAnswerRequest answerRequest : answers) {
            Optional<SecurityQuestion> questionOptional = securityQuestionRepository.findById(answerRequest.getQuestionId());
            if (questionOptional.isEmpty()) {
                throw new RuntimeException("Invalid question ID: " + answerRequest.getQuestionId());
            }
            
            UserSecurityAnswer userAnswer = new UserSecurityAnswer();
            userAnswer.setUser(user);
            userAnswer.setQuestion(questionOptional.get());
            userAnswer.setAnswerHash(passwordEncoder.encode(answerRequest.getAnswer().toLowerCase().trim()));
            
            userSecurityAnswerRepository.save(userAnswer);
        }
        
        // Update user security questions status
        user.setSecurityQuestionsSet(true);
        userRepository.save(user);
    }
    
    public List<SecurityQuestion> getUserSecurityQuestions(Long userId) {
        return userSecurityAnswerRepository.findSecurityQuestionsByUserId(userId);
    }
    
    public boolean validateSecurityAnswers(Long userId, List<SecurityAnswerRequest> answers) {
        for (SecurityAnswerRequest answer : answers) {
            Optional<String> storedHashOptional = userSecurityAnswerRepository
                .findAnswerHashByUserIdAndQuestionId(userId, answer.getQuestionId());
            
            if (storedHashOptional.isEmpty()) {
                return false;
            }
            
            String providedAnswer = answer.getAnswer().toLowerCase().trim();
            if (!passwordEncoder.matches(providedAnswer, storedHashOptional.get())) {
                return false;
            }
        }
        return true;
    }
    
    public boolean hasSecurityQuestionsSet(Long userId) {
        return userSecurityAnswerRepository.countByUserId(userId) >= 3;
    }
}