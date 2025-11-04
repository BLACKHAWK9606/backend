package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.SecurityAnswerRequest;
import com.bancassurance.authentication.models.SecurityQuestion;
import com.bancassurance.authentication.repositories.UserRepository;
import com.bancassurance.authentication.repositories.RoleRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LdapAuthenticationService ldapAuthenticationService;
    private SecurityQuestionService securityQuestionService;
    private final RoleRepository roleRepository;
    
    // Store reset tokens in memory (for development only)
    private final Map<String, PasswordResetToken> resetTokens = new HashMap<>();

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, 
                       JwtService jwtService, LdapAuthenticationService ldapAuthenticationService,
                       RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.ldapAuthenticationService = ldapAuthenticationService;
        this.roleRepository = roleRepository;
        this.securityQuestionService = null; // Will be injected via setter to avoid circular dependency
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
        
        User user = userOptional.get();
        if (user.getAuthenticationSource() != AuthenticationSource.EMAIL) {
            throw new RuntimeException("User account is not configured for email authentication");
        }
        
        return authenticateUser(user, password);
    }
    
    private Map<String, Object> loginWithPhone(String phoneNumber, String password) {
        Optional<User> userOptional = userRepository.findByPhoneNumber(phoneNumber);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with phone number: " + phoneNumber);
        }
        
        User user = userOptional.get();
        if (user.getAuthenticationSource() != AuthenticationSource.PHONE) {
            throw new RuntimeException("User account is not configured for phone authentication");
        }
        
        return authenticateUser(user, password);
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
    
    @Transactional
    public Map<String, Object> loginWithAD(String email, String password) {
        System.out.println("=== AD LOGIN START ===");
        System.out.println("AD Login: Email = " + email);
        
        if (email == null || password == null || email.trim().isEmpty() || password.trim().isEmpty()) {
            System.out.println("AD Login: ERROR - Missing credentials");
            throw new RuntimeException("Email and password are required");
        }
        
        // Authenticate against Active Directory
        System.out.println("AD Login: Step 1 - Authenticating against AD server...");
        if (!ldapAuthenticationService.authenticateUser(email, password)) {
            System.out.println("AD Login: ERROR - Authentication failed");
            throw new RuntimeException("Invalid Active Directory credentials");
        }
        System.out.println("AD Login: Step 1 - Authentication SUCCESS");
        
        // Get user details from AD
        System.out.println("AD Login: Step 2 - Getting user details from AD...");
        Map<String, Object> adUserDetails = ldapAuthenticationService.getUserDetails(email);
        if (adUserDetails == null) {
            System.out.println("AD Login: ERROR - Could not retrieve user details");
            throw new RuntimeException("Unable to retrieve user details from Active Directory");
        }
        System.out.println("AD Login: Step 2 - User details retrieved: " + adUserDetails);
        
        String userName = (String) adUserDetails.get("name");
        // Note: Role mapping will be handled later when we implement AD groups
        
        if (userName == null || userName.trim().isEmpty()) {
            userName = email.split("@")[0]; // Fallback to email prefix
        }
        
        // Extract AD user information
        String firstName = (String) adUserDetails.get("firstName");
        String lastName = (String) adUserDetails.get("lastName");
        String phoneNumber = (String) adUserDetails.get("phoneNumber");
        @SuppressWarnings("unchecked")
        List<String> adGroups = (List<String>) adUserDetails.get("groups");
        
        System.out.println("AD Login: Step 3 - Extracted user info:");
        System.out.println("  - First Name: " + firstName);
        System.out.println("  - Last Name: " + lastName);
        System.out.println("  - Phone: " + phoneNumber);
        System.out.println("  - AD Groups: " + adGroups);
        
        // Map AD groups to database role
        System.out.println("AD Login: Step 4 - Mapping AD groups to database role...");
        Role userRole = mapAdGroupsToRole(adGroups);
        System.out.println("AD Login: Step 4 - Mapped to role: " + userRole.getRoleName() + " (ID: " + userRole.getRoleId() + ")");
        
        // Check if user exists in local database
        System.out.println("AD Login: Step 5 - Checking if user exists in database...");
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;
        
        if (userOptional.isEmpty()) {
            System.out.println("AD Login: Step 5 - User NOT found in database, creating new user...");
            // Create new AD user in database
            user = createAdUser(email, firstName, lastName, phoneNumber, userRole);
            System.out.println("AD Login: Step 5 - New user created with ID: " + user.getUserId());
        } else {
            System.out.println("AD Login: Step 5 - User FOUND in database, updating...");
            user = userOptional.get();
            System.out.println("AD Login: Step 5 - Existing user ID: " + user.getUserId() + ", Auth Source: " + user.getAuthenticationSource());
            
            if (user.getAuthenticationSource() != AuthenticationSource.ACTIVE_DIRECTORY) {
                System.out.println("AD Login: ERROR - User auth source mismatch: " + user.getAuthenticationSource());
                throw new RuntimeException("User account is not configured for Active Directory authentication");
            }
            if (!user.getIsActive()) {
                System.out.println("AD Login: ERROR - User account is inactive");
                throw new RuntimeException("User account is deactivated");
            }
            // Update user details from AD
            updateAdUser(user, firstName, lastName, phoneNumber, userRole);
            System.out.println("AD Login: Step 5 - User updated successfully");
        }
        
        // Update last login directly in database
        System.out.println("AD Login: Step 6 - Updating last login timestamp...");
        userRepository.updateLastLogin(user.getUserId(), LocalDateTime.now());
        
        System.out.println("AD Login: Step 7 - Generating JWT tokens...");
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
        response.put("isFirstLogin", false);
        response.put("authSource", "ACTIVE_DIRECTORY");
        
        System.out.println("AD Login: Step 8 - SUCCESS! Final response:");
        System.out.println("  - User ID: " + user.getUserId());
        System.out.println("  - Username: " + user.getUsername());
        System.out.println("  - Email: " + user.getEmail());
        System.out.println("  - Role: " + user.getRole().getRoleName());
        System.out.println("  - Auth Source: ACTIVE_DIRECTORY");
        System.out.println("=== AD LOGIN COMPLETE ===");
        
        return response;
    }
    
    private Role mapAdGroupsToRole(List<String> adGroups) {
        System.out.println("Role Mapping: Starting group-to-role mapping...");
        
        // Dynamic group-to-role mapping
        Map<String, String> groupRoleMapping = Map.of(
            "Bancassurance-SUPERUSER", "SUPERUSER",
            "Bancassurance-POLICY_MANAGER", "POLICY_MANAGER",
            "Bancassurance-POLICY_OFFICER", "POLICY_OFFICER",
            "Bancassurance-VIEWER", "VIEWER",
            "Bancassurance-CLAIMS_OFFICER", "CLAIMS_OFFICER"
        );
        
        System.out.println("Role Mapping: Available mappings: " + groupRoleMapping);
        
        // Find highest priority role (SUPERUSER > POLICY_MANAGER > POLICY_OFFICER > CLAIMS_OFFICER > VIEWER)
        String[] rolePriority = {"SUPERUSER", "POLICY_MANAGER", "POLICY_OFFICER", "CLAIMS_OFFICER", "VIEWER"};
        
        for (String priorityRole : rolePriority) {
            System.out.println("Role Mapping: Checking priority role: " + priorityRole);
            for (String adGroup : adGroups) {
                System.out.println("Role Mapping: Checking AD group: " + adGroup + " against role: " + priorityRole);
                if (priorityRole.equals(groupRoleMapping.get(adGroup))) {
                    System.out.println("Role Mapping: MATCH found! " + adGroup + " -> " + priorityRole);
                    Optional<Role> role = roleRepository.findByRoleName(priorityRole);
                    if (role.isPresent()) {
                        System.out.println("Role Mapping: Database role found: " + role.get().getRoleName() + " (ID: " + role.get().getRoleId() + ")");
                        return role.get();
                    } else {
                        System.out.println("Role Mapping: WARNING - Role " + priorityRole + " not found in database!");
                    }
                }
            }
        }
        
        // Default to VIEWER role
        System.out.println("Role Mapping: No matches found, using default VIEWER role");
        return roleRepository.findByRoleName("VIEWER")
            .orElseThrow(() -> new RuntimeException("Default VIEWER role not found"));
    }
    
    private User createAdUser(String email, String firstName, String lastName, String phoneNumber, Role role) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(email.split("@")[0]); // Use email prefix as username
        user.setFirstName(firstName != null ? firstName : "AD");
        user.setLastName(lastName != null ? lastName : "User");
        user.setPhoneNumber(phoneNumber);
        user.setRole(role);
        user.setAuthenticationSource(AuthenticationSource.ACTIVE_DIRECTORY);
        user.setIsActive(true);
        user.setIsApproved(true); // Auto-approve AD users
        user.setIsFirstLogin(false);
        user.setSecurityQuestionsSet(false);
        user.setSecurityQuestionsMandatory(false); // AD users don't need security questions
        
        return userRepository.save(user);
    }
    
    private void updateAdUser(User user, String firstName, String lastName, String phoneNumber, Role role) {
        // Update user details from AD
        if (firstName != null) user.setFirstName(firstName);
        if (lastName != null) user.setLastName(lastName);
        if (phoneNumber != null) user.setPhoneNumber(phoneNumber);
        
        // Update role if changed
        if (!user.getRole().getRoleName().equals(role.getRoleName())) {
            user.setRole(role);
        }
        
        userRepository.save(user);
    }
    @Transactional
    public Map<String, Object> forgotPassword(String identifier) {
        Optional<User> userOptional = userRepository.findByIdentifier(identifier);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with identifier: " + identifier);
        }
        
        User user = userOptional.get();
        
        if (!user.getIsActive()) {
            throw new RuntimeException("User account is deactivated");
        }
        
        // Check if user has security questions set
        if (securityQuestionService != null && securityQuestionService.hasSecurityQuestionsSet(user.getUserId())) {
            // Get user's security questions (NO TOKEN GENERATED HERE)
            List<SecurityQuestion> questions = securityQuestionService.getUserSecurityQuestions(user.getUserId());
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Please answer your security questions to proceed");
            response.put("questions", questions.stream().map(q -> Map.of(
                "id", q.getQuestionId(),
                "text", q.getQuestionText()
            )).toList());
            response.put("requiresSecurityVerification", true);
            response.put("identifier", identifier);
            response.put("attemptsAllowed", 3);
            
            return response;
        } else {
            // Fallback to traditional token-based reset for users without security questions
            String token = UUID.randomUUID().toString();
            resetTokens.put(token, new PasswordResetToken(user.getEmail(), LocalDateTime.now().plusHours(24)));
            userRepository.updatePasswordResetTokenById(user.getUserId(), token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Password reset token generated successfully");
            response.put("token", token);
            response.put("email", user.getEmail());
            response.put("requiresSecurityVerification", false);
            
            return response;
        }
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
    
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        // Blacklist access token
        jwtService.blacklistToken(accessToken);
        
        // Blacklist refresh token if provided
        if (refreshToken != null && !refreshToken.trim().isEmpty()) {
            jwtService.blacklistToken(refreshToken);
        }
    }
    
    @Transactional
    public Map<String, Object> refreshToken(String refreshToken) {
        if (jwtService.isTokenBlacklisted(refreshToken)) {
            throw new RuntimeException("Refresh token has been invalidated");
        }
        
        if (jwtService.isTokenExpired(refreshToken)) {
            throw new RuntimeException("Refresh token has expired");
        }
        
        String tokenType = jwtService.getTokenType(refreshToken);
        if (!"refresh".equals(tokenType)) {
            throw new RuntimeException("Invalid token type");
        }
        
        String email = jwtService.extractUsername(refreshToken);
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        
        User user = userOptional.get();
        if (!user.getIsActive() || user.getIsDeleted() || !user.getIsApproved()) {
            throw new RuntimeException("User account is not active");
        }
        
        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);
        
        // Blacklist old refresh token
        jwtService.blacklistToken(refreshToken);
        
        Map<String, Object> response = new HashMap<>();
        response.put("accessToken", newAccessToken);
        response.put("refreshToken", newRefreshToken);
        response.put("tokenType", "Bearer");
        response.put("expiresIn", 900); // 15 minutes
        
        return response;
    }
    

    
    @Transactional
    public Map<String, Object> verifySecurityAnswers(String identifier, List<SecurityAnswerRequest> answers) {
        Optional<User> userOptional = userRepository.findByIdentifier(identifier);
        
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found with identifier: " + identifier);
        }
        
        User user = userOptional.get();
        
        if (!user.getIsActive()) {
            throw new RuntimeException("User account is deactivated");
        }
        
        if (!securityQuestionService.validateSecurityAnswers(user.getUserId(), answers)) {
            Map<String, Object> response = new HashMap<>();
            response.put("verified", false);
            response.put("message", "One or more security answers are incorrect");
            response.put("attemptsRemaining", 2);
            return response;
        }
        
        // Generate THE password reset token (this is the token for reset-password endpoint)
        String passwordResetToken = UUID.randomUUID().toString();
        resetTokens.put(passwordResetToken, new PasswordResetToken(user.getEmail(), LocalDateTime.now().plusMinutes(15)));
        
        // CRITICAL: Store token in database for reset-password endpoint to work
        userRepository.updatePasswordResetTokenById(user.getUserId(), passwordResetToken);
        
        Map<String, Object> response = new HashMap<>();
        response.put("verified", true);
        response.put("message", "Security questions verified successfully");
        response.put("passwordResetToken", passwordResetToken);
        response.put("tokenExpiresIn", 900);
        
        return response;
    }
    
    @Transactional
    public Map<String, Object> registerUser(Map<String, String> registerRequest) {
        String username = registerRequest.get("username");
        String email = registerRequest.get("email");
        String password = registerRequest.get("password");
        String firstName = registerRequest.get("firstName");
        String lastName = registerRequest.get("lastName");
        
        if (username == null || email == null || password == null) {
            throw new RuntimeException("Username, email, and password are required");
        }
        
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists");
        }
        
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists");
        }
        
        // Get default role (assuming USER role exists)
        Optional<Role> defaultRole = roleRepository.findByRoleName("USER");
        if (defaultRole.isEmpty()) {
            throw new RuntimeException("Default user role not found");
        }
        
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setRole(defaultRole.get());
        user.setAuthenticationSource(AuthenticationSource.EMAIL);
        user.setSecurityQuestionsSet(false);
        user.setSecurityQuestionsMandatory(true);
        
        User savedUser = userRepository.save(user);
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Account created successfully. Please set up security questions.");
        response.put("userId", savedUser.getUserId());
        response.put("requiresSecuritySetup", true);
        response.put("nextStep", "security_questions_setup");
        
        return response;
    }
    
    public void setSecurityQuestionService(SecurityQuestionService securityQuestionService) {
        this.securityQuestionService = securityQuestionService;
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