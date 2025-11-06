package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.OtpPurpose;
import com.bancassurance.authentication.models.TempToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class TwoFactorService {
    
    private final OtpService otpService;
    private final TempTokenService tempTokenService;
    private final JwtService jwtService;
    private final UserService userService;
    
    public TwoFactorService(OtpService otpService, TempTokenService tempTokenService, 
                           JwtService jwtService, UserService userService) {
        this.otpService = otpService;
        this.tempTokenService = tempTokenService;
        this.jwtService = jwtService;
        this.userService = userService;
    }
    
    @Transactional
    public Map<String, Object> initiate2FA(User user) {
        // Generate and send OTP
        otpService.generateAndSendOtp(user, OtpPurpose.LOGIN);
        
        // Generate temporary token (5 minutes expiry)
        String tempToken = tempTokenService.generateTempToken(
            user.getUserId(), 
            "LOGIN", 
            user.getEmail(), 
            5
        );
        
        Map<String, Object> response = new HashMap<>();
        response.put("requiresOtp", true);
        response.put("tempToken", tempToken);
        response.put("otpMethod", "SMS");
        response.put("message", "OTP sent to your registered phone number");
        response.put("expiresIn", 300); // 5 minutes in seconds
        
        return response;
    }
    
    @Transactional
    public Map<String, Object> verifyOtpAndIssueTokens(String tempToken, String otpCode) {
        // Validate temporary token
        Optional<TempToken> tempTokenOpt = tempTokenService.validateAndConsumeTempToken(tempToken, "LOGIN");
        
        if (tempTokenOpt.isEmpty()) {
            throw new RuntimeException("Invalid or expired temporary token");
        }
        
        TempToken validTempToken = tempTokenOpt.get();
        
        // Validate OTP
        boolean otpValid = otpService.validateOtp(validTempToken.getUserId(), otpCode, OtpPurpose.LOGIN);
        
        if (!otpValid) {
            throw new RuntimeException("Invalid or expired OTP code");
        }
        
        // Get user and generate JWT tokens
        Optional<User> userOpt = userService.getUserById(validTempToken.getUserId());
        if (userOpt.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        
        User user = userOpt.get();
        
        // Generate JWT tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        response.put("tokenType", "Bearer");
        response.put("expiresIn", 900); // 15 minutes in seconds
        response.put("userId", user.getUserId().toString());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("roleName", user.getRole().getRoleName());
        response.put("isFirstLogin", user.getIsFirstLogin());
        response.put("authSource", user.getAuthenticationSource().toString());
        
        return response;
    }
}