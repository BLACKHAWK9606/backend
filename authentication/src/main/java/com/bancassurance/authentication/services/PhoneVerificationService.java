package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.OtpPurpose;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.RoleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class PhoneVerificationService {
    
    private final OtpService otpService;
    private final TempTokenService tempTokenService;
    private final UserService userService;
    private final RoleRepository roleRepository;
    
    public PhoneVerificationService(OtpService otpService, TempTokenService tempTokenService, 
                                   UserService userService, RoleRepository roleRepository) {
        this.otpService = otpService;
        this.tempTokenService = tempTokenService;
        this.userService = userService;
        this.roleRepository = roleRepository;
    }
    
    @Transactional
    public Map<String, Object> initiatePhoneVerification(String phoneNumber, Map<String, Object> userData) {
        // Generate and send OTP to phone number
        otpService.generateAndSendOtpForPhone(phoneNumber, OtpPurpose.PHONE_VERIFICATION);
        
        // Generate temporary token (10 minutes expiry for registration)
        String tempToken = tempTokenService.generateTempToken(
            null, // No user ID yet
            "REGISTRATION", 
            (String) userData.get("email"), 
            10
        );
        
        // Store user data temporarily (we'll need this when creating the user)
        storeTemporaryUserData(tempToken, userData);
        
        Map<String, Object> response = new HashMap<>();
        response.put("requiresPhoneVerification", true);
        response.put("tempToken", tempToken);
        response.put("otpMethod", "SMS");
        response.put("message", "OTP sent to " + maskPhoneNumber(phoneNumber));
        response.put("expiresIn", 600); // 10 minutes in seconds
        
        return response;
    }
    
    @Transactional
    public Map<String, Object> verifyPhoneAndCreateUser(String tempToken, String otpCode) {
        // Validate temporary token
        Optional<com.bancassurance.authentication.models.TempToken> tempTokenOpt = 
            tempTokenService.validateAndConsumeTempToken(tempToken, "REGISTRATION");
        
        if (tempTokenOpt.isEmpty()) {
            throw new RuntimeException("Invalid or expired temporary token");
        }
        
        com.bancassurance.authentication.models.TempToken validTempToken = tempTokenOpt.get();
        
        // Get stored user data
        Map<String, Object> userData = getTemporaryUserData(tempToken);
        if (userData == null) {
            throw new RuntimeException("User registration data not found");
        }
        
        String phoneNumber = (String) userData.get("phoneNumber");
        
        // Validate OTP
        boolean otpValid = otpService.validateOtpForPhone(phoneNumber, otpCode, OtpPurpose.PHONE_VERIFICATION);
        
        if (!otpValid) {
            throw new RuntimeException("Invalid or expired OTP code");
        }
        
        // Create user in database
        User createdUser = createUserFromData(userData);
        
        // Clean up temporary data
        cleanupTemporaryUserData(tempToken);
        
        Map<String, Object> response = new HashMap<>();
        response.put("user", createdUser);
        response.put("message", "User created successfully. Security questions setup required.");
        response.put("requiresSecuritySetup", !createdUser.getSecurityQuestionsSet());
        response.put("userId", createdUser.getUserId());
        
        return response;
    }
    
    // Temporary storage for user data during verification (in-memory for simplicity)
    private final Map<String, Map<String, Object>> tempUserData = new HashMap<>();
    
    private void storeTemporaryUserData(String tempToken, Map<String, Object> userData) {
        tempUserData.put(tempToken, userData);
    }
    
    private Map<String, Object> getTemporaryUserData(String tempToken) {
        return tempUserData.get(tempToken);
    }
    
    private void cleanupTemporaryUserData(String tempToken) {
        tempUserData.remove(tempToken);
    }
    
    private User createUserFromData(Map<String, Object> userData) {
        String username = (String) userData.get("username");
        String email = (String) userData.get("email");
        String phoneNumber = (String) userData.get("phoneNumber");
        String password = (String) userData.get("password");
        String firstName = (String) userData.get("firstName");
        String lastName = (String) userData.get("lastName");
        Long roleId = Long.valueOf(userData.get("roleId").toString());
        String authSourceStr = (String) userData.get("authSource");
        
        // Get role from repository
        Role role = roleRepository.findById(roleId)
            .orElseThrow(() -> new RuntimeException("Role not found with ID: " + roleId));
        
        AuthenticationSource authSource = AuthenticationSource.EMAIL;
        if (authSourceStr != null) {
            authSource = AuthenticationSource.valueOf(authSourceStr.toUpperCase());
        }
        
        User user = userService.registerUser(username, email, phoneNumber, password, role, authSource);
        
        // Set additional fields
        if (firstName != null) user.setFirstName(firstName);
        if (lastName != null) user.setLastName(lastName);
        
        return userService.updateUser(user);
    }
    
    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return phoneNumber;
        }
        return phoneNumber.substring(0, phoneNumber.length() - 4) + "****";
    }
}