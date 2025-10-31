package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.repositories.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    public User getCurrentUser(org.springframework.security.core.Authentication authentication) {
        String email = authentication.getName();
        return userRepository.findByEmailWithRole(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
    }

    public User registerUser(String username, String email, String phoneNumber, String password, Role role, AuthenticationSource authSource) {
        // Check for existing users
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email is already in use");
        }
        
        if (phoneNumber != null && userRepository.existsByPhoneNumber(phoneNumber)) {
            throw new RuntimeException("Phone number is already in use");
        }
        
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username is already in use");
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPhoneNumber(phoneNumber);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setAuthenticationSource(authSource != null ? authSource : AuthenticationSource.EMAIL);
        user.setIsActive(true);
        user.setIsFirstLogin(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setIsApproved(false); // Requires approval
        user.setIsDeleted(false);

        User savedUser = userRepository.save(user);
        // Return user with role eagerly loaded
        return userRepository.findByIdWithRole(savedUser.getUserId()).orElse(savedUser);
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findByIdWithRole(id);
    }

    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmailWithRole(email);
    }
    
    public Optional<User> getUserByPhoneNumber(String phoneNumber) {
        return userRepository.findByPhoneNumberWithRole(phoneNumber);
    }
    
    public Optional<User> getUserByIdentifier(String identifier) {
        return userRepository.findByIdentifierWithRole(identifier);
    }

    public List<User> getAllUsers() {
        return userRepository.findAllActiveUsersWithRole();
    }

    public List<User> getUsersByRole(Role role) {
        return userRepository.findByRoleWithRole(role);
    }

    public List<User> getActiveUsersByRole(Role role) {
        return userRepository.findByRoleAndIsActiveTrueWithRole(role);
    }

    public User updateUser(User user) {
        User savedUser = userRepository.save(user);
        // Return user with role eagerly loaded
        return userRepository.findByIdWithRole(savedUser.getUserId()).orElse(savedUser);
    }

    public void deactivateUser(Long userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setIsActive(false);
            userRepository.save(user);
        });
    }

    public void activateUser(Long userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setIsActive(true);
            userRepository.save(user);
        });
    }
    
    public void approveUser(Long userId, Long approvedBy) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setIsApproved(true);
            user.setApprovalTimestamp(LocalDateTime.now());
            User approver = userRepository.findById(approvedBy).orElse(null);
            user.setApprovedBy(approver);
            user.setIsRejected(false);
            userRepository.save(user);
        });
    }
    
    public void rejectUser(Long userId, Long rejectedBy, String reason) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setIsRejected(true);
            user.setRejectionTimestamp(LocalDateTime.now());
            User rejector = userRepository.findById(rejectedBy).orElse(null);
            user.setRejectedBy(rejector);
            user.setRejectionReason(reason);
            user.setIsApproved(false);
            userRepository.save(user);
        });
    }
    
    public void softDeleteUser(Long userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setIsDeleted(true);
            user.setIsActive(false);
            userRepository.save(user);
        });
    }

    public void updateLastLogin(User user) {
        user.setLastLogin(LocalDateTime.now());
        user.setIsLoggedIn(true);
        userRepository.save(user);
    }
    
    public void changePassword(String email, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setIsFirstLogin(false);
        userRepository.save(user);
    }
    
    public List<User> getPendingApprovalUsers() {
        return userRepository.findPendingApprovalUsersWithRole();
    }
    
    public long getActiveUserCount() {
        return userRepository.countActiveUsers();
    }

    public Map<String, Object> getUserProfile(String username) {
        Optional<User> userOptional = userRepository.findByUsernameWithRole(username);
        
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        
        User user = userOptional.get();
        return buildUserProfileResponse(user);
    }

    public Map<String, Object> getUserProfileById(Long userId, String currentUsername) {
        Optional<User> userOptional = userRepository.findByIdWithRole(userId);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found with ID: " + userId);
        }
        
        User user = userOptional.get();
        return buildUserProfileResponse(user);
    }

    public Map<String, Object> searchUsers(String email, String phone, String username, String currentUsername) {
        List<User> users;
        
        if (email != null && !email.trim().isEmpty()) {
            users = userRepository.findByEmailWithRole(email).map(List::of).orElse(List.of());
        } else if (phone != null && !phone.trim().isEmpty()) {
            users = userRepository.findByPhoneNumberWithRole(phone).map(List::of).orElse(List.of());
        } else if (username != null && !username.trim().isEmpty()) {
            users = userRepository.findByUsernameWithRole(username).map(List::of).orElse(List.of());
        } else {
            users = userRepository.findAllActiveUsersWithRole();
        }
        
        List<Map<String, Object>> userProfiles = users.stream()
            .map(this::buildUserProfileResponse)
            .collect(Collectors.toList());
        
        Map<String, Object> response = new HashMap<>();
        response.put("users", userProfiles);
        response.put("count", userProfiles.size());
        
        return response;
    }

    private Map<String, Object> buildUserProfileResponse(User user) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("userId", user.getUserId());
        profile.put("username", user.getUsername());
        profile.put("firstName", user.getFirstName());
        profile.put("lastName", user.getLastName());
        profile.put("email", user.getEmail());
        profile.put("phoneNumber", user.getPhoneNumber());
        profile.put("roleName", user.getRole().getRoleName());
        profile.put("authenticationSource", user.getAuthenticationSource().toString());
        profile.put("isActive", user.getIsActive());
        profile.put("isApproved", user.getIsApproved());
        profile.put("createdAt", user.getCreatedAt());
        profile.put("lastLogin", user.getLastLogin());
        return profile;
    }
}