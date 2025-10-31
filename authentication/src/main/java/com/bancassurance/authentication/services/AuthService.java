package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.repositories.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LdapAuthenticationService ldapAuthenticationService;
    
    // Store reset tokens in memory (for development only)
    private final Map<String, PasswordResetToken> resetTokens = new HashMap<>();

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, 
                       JwtService jwtService, LdapAuthenticationService ldapAuthenticationService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.ldapAuthenticationService = ldapAuthenticationService;
    }

    @Transactional
    public Map<String, Object> login(String identifier, String password, String authType) {
        AuthenticationSource authSource = AuthenticationSource.valueOf(authType.toUpperCase());
        
        switch (authSource) {
            case EMAIL:
                return loginWithEmail(identifier, password);
            case PHONE:
                return loginWithPhone(identifier, password);
            case ACTIVE_DIRECTORY:
                return loginWithAD(identifier, password);
            default:
                throw new RuntimeException("Unsupported authentication type: " + authType);
        }
    }
    
    private Map<String, Object> loginWithEmail(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with email: " + email);
        }
        
        return authenticateUser(userOptional.get(), password);
    }
    
    private Map<String, Object> loginWithPhone(String phoneNumber, String password) {
        Optional<User> userOptional = userRepository.findByPhoneNumber(phoneNumber);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with phone number: " + phoneNumber);
        }
        
        return authenticateUser(userOptional.get(), password);
    }
    
    @Transactional
    private Map<String, Object> authenticateUser(User user, String password) {
        if (!user.getIsActive()) {
            throw new RuntimeException("User account is deactivated");
        }
        
        if (user.getIsDeleted()) {
            throw new RuntimeException("User account has been deleted");
        }
        
        if (!user.getIsApproved()) {
            throw new RuntimeException("User account is pending approval");
        }
        
        if (user.getIsRejected()) {
            throw new RuntimeException("User account has been rejected");
        }
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        
        // Update last login directly in database
        userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now());
        
        String token = jwtService.generateToken(user);
        
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("userId", user.getUserId().toString());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("roleName", user.getRole().getRoleName());
        response.put("isFirstLogin", user.getIsFirstLogin());
        response.put("authSource", user.getAuthenticationSource().toString());
        
        return response;
    }
    
    @Transactional
    public Map<String, Object> loginWithAD(String email, String password) {
        if (email == null || password == null || email.trim().isEmpty() || password.trim().isEmpty()) {
            throw new RuntimeException("Email and password are required");
        }
        
        // Authenticate against Active Directory
        if (!ldapAuthenticationService.authenticateUser(email, password)) {
            throw new RuntimeException("Invalid Active Directory credentials");
        }
        
        // Get user details from AD
        Map<String, Object> adUserDetails = ldapAuthenticationService.getUserDetails(email);
        if (adUserDetails == null) {
            throw new RuntimeException("Unable to retrieve user details from Active Directory");
        }
        
        String userName = (String) adUserDetails.get("name");
        // Note: Role mapping will be handled later when we implement AD groups
        
        if (userName == null || userName.trim().isEmpty()) {
            userName = email.split("@")[0]; // Fallback to email prefix
        }
        
        // Check if user exists in local database
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;
        
        if (userOptional.isEmpty()) {
            // Create new user from AD details - will need default role
            throw new RuntimeException("AD user sync not fully implemented. Please contact administrator.");
        } else {
            user = userOptional.get();
            if (!user.getIsActive()) {
                throw new RuntimeException("User account is deactivated");
            }
            // Update user details from AD directly in database
            userRepository.updateFirstName(user.getUserId(), userName);
        }
        
        // Update last login directly in database
        userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now());
        
        String token = jwtService.generateToken(user);
        
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("userId", user.getUserId().toString());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("roleName", user.getRole().getRoleName());
        response.put("isFirstLogin", false);
        response.put("authType", "AD");
        
        return response;
    }
    @Transactional
    public Map<String, String> forgotPassword(String identifier) {
        Optional<User> userOptional = userRepository.findByIdentifier(identifier);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with identifier: " + identifier);
        }
        
        User user = userOptional.get();
        
        if (!user.getIsActive()) {
            throw new RuntimeException("User account is deactivated");
        }
        
        // Generate a unique token
        String token = UUID.randomUUID().toString();
        
        // Store token with user email and expiration time (24 hours from now)
        resetTokens.put(token, new PasswordResetToken(user.getEmail(), LocalDateTime.now().plusHours(24)));
        
        // Update only the reset token field directly in database
        userRepository.updatePasswordResetTokenById(user.getUserId(), token);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Password reset token generated successfully");
        response.put("token", token);
        response.put("email", user.getEmail());
        
        return response;
    }
    
    @Transactional
    public Map<String, String> resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = resetTokens.get(token);
        
        if (resetToken == null) {
            throw new RuntimeException("Invalid or expired password reset token");
        }
        
        if (resetToken.isExpired()) {
            resetTokens.remove(token);
            throw new RuntimeException("Password reset token has expired");
        }
        
        Optional<User> userOptional = userRepository.findByEmail(resetToken.getEmail());
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with email: " + resetToken.getEmail());
        }
        
        User user = userOptional.get();
        
        // Update password and clear token directly in database
        userRepository.updatePasswordAndClearToken(user.getUserId(), passwordEncoder.encode(newPassword));
        
        // Remove the used token
        resetTokens.remove(token);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Password has been reset successfully");
        
        return response;
    }
    
    public boolean validateResetToken(String token) {
        PasswordResetToken resetToken = resetTokens.get(token);
        return resetToken != null && !resetToken.isExpired();
    }
    
    /**
     * Inner class to store password reset token information
     */
    private static class PasswordResetToken {
        private final String email;
        private final LocalDateTime expiryDate;
        
        public PasswordResetToken(String email, LocalDateTime expiryDate) {
            this.email = email;
            this.expiryDate = expiryDate;
        }
        
        public String getEmail() {
            return email;
        }
        
        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryDate);
        }
    }
}