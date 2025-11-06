package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.OtpPurpose;
import com.bancassurance.authentication.models.TempToken;
import com.bancassurance.authentication.models.SecurityQuestion;
import com.bancassurance.authentication.repositories.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class PasswordResetService {
    
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);
    private final OtpService otpService;
    private final TempTokenService tempTokenService;
    private final UserRepository userRepository;
    private SecurityQuestionService securityQuestionService;
    
    public PasswordResetService(OtpService otpService, TempTokenService tempTokenService, 
                               UserRepository userRepository) {
        this.otpService = otpService;
        this.tempTokenService = tempTokenService;
        this.userRepository = userRepository;
    }
    
    public void setSecurityQuestionService(SecurityQuestionService securityQuestionService) {
        this.securityQuestionService = securityQuestionService;
    }
    
    @Transactional
    public Map<String, Object> initiatePasswordResetWithOtp(String identifier) {
        Optional<User> userOptional = userRepository.findByIdentifier(identifier);
        
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with identifier: " + identifier);
        }
        
        User user = userOptional.get();
        
        if (!user.getIsActive()) {
            throw new RuntimeException("User account is deactivated");
        }
        
        // Generate and send OTP for password reset
        otpService.generateAndSendOtp(user, OtpPurpose.PASSWORD_RESET);
        
        // Generate temporary token (15 minutes expiry for password reset)
        String tempToken = tempTokenService.generateTempToken(
            user.getUserId(), 
            "PASSWORD_RESET", 
            user.getEmail(), 
            15
        );
        
        Map<String, Object> response = new HashMap<>();
        response.put("requiresOtpVerification", true);
        response.put("tempResetToken", tempToken);
        response.put("otpMethod", "SMS");
        response.put("message", "OTP sent to your registered phone number for identity verification");
        response.put("expiresIn", 900); // 15 minutes in seconds
        
        return response;
    }
    
    @Transactional
    public Map<String, Object> verifyResetOtpAndGetSecurityQuestions(String tempToken, String otpCode) {
        logger.info("=== PASSWORD RESET OTP VERIFICATION START ===");
        logger.info("Temp Token: {}", tempToken);
        logger.info("OTP Code: {}", otpCode);
        
        try {
            // Validate temporary token
            logger.info("Step 1: Validating temporary token...");
            Optional<TempToken> tempTokenOpt = tempTokenService.validateAndConsumeTempToken(tempToken, "PASSWORD_RESET");
            
            if (tempTokenOpt.isEmpty()) {
                logger.error("Temporary token validation failed");
                throw new RuntimeException("Invalid or expired temporary token");
            }
            
            TempToken validTempToken = tempTokenOpt.get();
            logger.info("Step 1: Temporary token valid for user ID: {}", validTempToken.getUserId());
            
            // Validate OTP
            logger.info("Step 2: Validating OTP for user ID: {}", validTempToken.getUserId());
            boolean otpValid = otpService.validateOtp(validTempToken.getUserId(), otpCode, OtpPurpose.PASSWORD_RESET);
            
            if (!otpValid) {
                logger.error("OTP validation failed for user ID: {}", validTempToken.getUserId());
                throw new RuntimeException("Invalid or expired OTP code");
            }
            
            logger.info("Step 2: OTP validation successful");
            
            // Get user
            logger.info("Step 3: Getting user details for ID: {}", validTempToken.getUserId());
            Optional<User> userOptional = userRepository.findById(validTempToken.getUserId());
            if (userOptional.isEmpty()) {
                logger.error("User not found with ID: {}", validTempToken.getUserId());
                throw new RuntimeException("User not found");
            }
            
            User user = userOptional.get();
            logger.info("Step 3: User found: {}", user.getEmail());
            
            // Check if user has security questions set
            logger.info("Step 4: Checking if user has security questions set...");
            if (securityQuestionService != null && securityQuestionService.hasSecurityQuestionsSet(user.getUserId())) {
                logger.info("Step 4: User has security questions set");
            // Get user's security questions
            List<SecurityQuestion> questions = securityQuestionService.getUserSecurityQuestions(user.getUserId());
            
            Map<String, Object> response = new HashMap<>();
            response.put("verified", true);
            response.put("message", "OTP verified successfully. Please answer your security questions to proceed");
            response.put("questions", questions.stream().map(q -> Map.of(
                "id", q.getQuestionId(),
                "text", q.getQuestionText()
            )).toList());
            response.put("requiresSecurityVerification", true);
            response.put("identifier", validTempToken.getUserEmail());
            response.put("attemptsAllowed", 3);
            
                logger.info("=== PASSWORD RESET OTP VERIFICATION SUCCESS (Security Questions) ===");
                return response;
            } else {
                logger.info("Step 4: User has no security questions, generating direct reset token");
            // Fallback: generate traditional reset token directly
            String resetToken = java.util.UUID.randomUUID().toString();
            
            // Store reset token in user record
            userRepository.updatePasswordResetTokenById(user.getUserId(), resetToken);
            
            Map<String, Object> response = new HashMap<>();
            response.put("verified", true);
            response.put("message", "OTP verified successfully. You can now reset your password");
            response.put("passwordResetToken", resetToken);
            response.put("requiresSecurityVerification", false);
            
                logger.info("=== PASSWORD RESET OTP VERIFICATION SUCCESS (Direct Reset) ===");
                return response;
            }
        } catch (Exception e) {
            logger.error("=== PASSWORD RESET OTP VERIFICATION FAILED ===");
            logger.error("Error Type: {}", e.getClass().getSimpleName());
            logger.error("Error Message: {}", e.getMessage());
            logger.error("Full Stack Trace:", e);
            throw e;
        }
    }
}