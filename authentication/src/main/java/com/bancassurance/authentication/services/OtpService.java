package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.OtpToken;
import com.bancassurance.authentication.models.OtpPurpose;
import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.OtpTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {
    
    private final OtpTokenRepository otpTokenRepository;
    private final EmTechSmsService emTechSmsService;
    private final SecureRandom secureRandom = new SecureRandom();
    
    @Value("${otp.length}")
    private int otpLength;
    
    @Value("${otp.expiry-minutes.login}")
    private int loginExpiryMinutes;
    
    @Value("${otp.expiry-minutes.phone-verification}")
    private int phoneVerificationExpiryMinutes;
    
    @Value("${otp.expiry-minutes.password-reset}")
    private int passwordResetExpiryMinutes;
    
    @Value("${otp.max-attempts}")
    private int maxAttempts;
    
    @Value("${otp.development-mode:false}")
    private boolean developmentMode;
    
    public OtpService(OtpTokenRepository otpTokenRepository, EmTechSmsService emTechSmsService) {
        this.otpTokenRepository = otpTokenRepository;
        this.emTechSmsService = emTechSmsService;
    }
    
    @Transactional
    public OtpToken generateAndSendOtp(User user, OtpPurpose purpose) {
        // Expire existing tokens for this user and purpose
        otpTokenRepository.expireUserTokensForPurpose(user.getUserId(), purpose);
        
        // Generate new OTP
        String otpCode = generateOtpCode();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(getExpiryMinutes(purpose));
        
        OtpToken otpToken = new OtpToken();
        otpToken.setUser(user);
        otpToken.setPhoneNumber(user.getPhoneNumber());
        otpToken.setOtpCode(otpCode);
        otpToken.setPurpose(purpose);
        otpToken.setExpiresAt(expiresAt);
        otpToken.setMaxAttempts(maxAttempts);
        
        OtpToken savedToken = otpTokenRepository.save(otpToken);
        
        // Send SMS or log in development mode
        if (developmentMode) {
            System.out.println("\n=== DEVELOPMENT MODE - OTP NOT SENT ====");
            System.out.println("Phone: " + user.getPhoneNumber());
            System.out.println("OTP Code: " + otpCode);
            System.out.println("Purpose: " + purpose);
            System.out.println("Message: Your BANCASSUR verification code is: " + otpCode + ". Valid for 5 minutes. Do not share this code.");
            System.out.println("========================================\n");
        } else {
            emTechSmsService.sendOtpSms(user.getPhoneNumber(), otpCode);
        }
        
        return savedToken;
    }
    
    @Transactional
    public OtpToken generateAndSendOtpForPhone(String phoneNumber, OtpPurpose purpose) {
        // For phone verification during registration (no user exists yet)
        String otpCode = generateOtpCode();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(getExpiryMinutes(purpose));
        
        OtpToken otpToken = new OtpToken();
        otpToken.setPhoneNumber(phoneNumber);
        otpToken.setOtpCode(otpCode);
        otpToken.setPurpose(purpose);
        otpToken.setExpiresAt(expiresAt);
        otpToken.setMaxAttempts(maxAttempts);
        
        OtpToken savedToken = otpTokenRepository.save(otpToken);
        
        // Send SMS or log in development mode
        if (developmentMode) {
            System.out.println("\n=== DEVELOPMENT MODE - OTP NOT SENT ====");
            System.out.println("Phone: " + phoneNumber);
            System.out.println("OTP Code: " + otpCode);
            System.out.println("Purpose: " + purpose);
            System.out.println("Message: Your BANCASSUR verification code is: " + otpCode + ". Valid for 5 minutes. Do not share this code.");
            System.out.println("========================================\n");
        } else {
            emTechSmsService.sendOtpSms(phoneNumber, otpCode);
        }
        
        return savedToken;
    }
    
    @Transactional
    public boolean validateOtp(Long userId, String otpCode, OtpPurpose purpose) {
        Optional<OtpToken> tokenOptional = otpTokenRepository
            .findByUserUserIdAndPurposeAndIsVerifiedFalseAndIsExpiredFalse(userId, purpose);
        
        if (tokenOptional.isEmpty()) {
            return false;
        }
        
        OtpToken token = tokenOptional.get();
        
        // Check if expired
        if (token.isExpired()) {
            token.setIsExpired(true);
            otpTokenRepository.save(token);
            return false;
        }
        
        // Increment attempts
        token.setAttempts(token.getAttempts() + 1);
        
        // Check if max attempts exceeded
        if (token.hasExceededMaxAttempts()) {
            token.setIsExpired(true);
            otpTokenRepository.save(token);
            return false;
        }
        
        // Validate OTP code
        if (otpCode.equals(token.getOtpCode())) {
            token.setIsVerified(true);
            token.setVerifiedAt(LocalDateTime.now());
            otpTokenRepository.save(token);
            return true;
        } else {
            otpTokenRepository.save(token);
            return false;
        }
    }
    
    @Transactional
    public boolean validateOtpForPhone(String phoneNumber, String otpCode, OtpPurpose purpose) {
        Optional<OtpToken> tokenOptional = otpTokenRepository
            .findByPhoneNumberAndPurposeAndIsVerifiedFalseAndIsExpiredFalse(phoneNumber, purpose);
        
        if (tokenOptional.isEmpty()) {
            return false;
        }
        
        OtpToken token = tokenOptional.get();
        
        // Check if expired
        if (token.isExpired()) {
            token.setIsExpired(true);
            otpTokenRepository.save(token);
            return false;
        }
        
        // Increment attempts
        token.setAttempts(token.getAttempts() + 1);
        
        // Check if max attempts exceeded
        if (token.hasExceededMaxAttempts()) {
            token.setIsExpired(true);
            otpTokenRepository.save(token);
            return false;
        }
        
        // Validate OTP code
        if (otpCode.equals(token.getOtpCode())) {
            token.setIsVerified(true);
            token.setVerifiedAt(LocalDateTime.now());
            otpTokenRepository.save(token);
            return true;
        } else {
            otpTokenRepository.save(token);
            return false;
        }
    }
    
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        otpTokenRepository.expireOldTokens(now);
        
        // Delete tokens older than 24 hours
        LocalDateTime cutoff = now.minusHours(24);
        otpTokenRepository.deleteOldTokens(cutoff);
    }
    
    private String generateOtpCode() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }
    
    private int getExpiryMinutes(OtpPurpose purpose) {
        return switch (purpose) {
            case LOGIN -> loginExpiryMinutes;
            case PHONE_VERIFICATION -> phoneVerificationExpiryMinutes;
            case PASSWORD_RESET -> passwordResetExpiryMinutes;
        };
    }
}