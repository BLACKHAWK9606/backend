package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.services.UserService;
import com.bancassurance.authentication.repositories.RoleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
@Tag(name = "User Management", description = "User CRUD operations and lifecycle management")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {
    
    private final UserService userService;
    private final RoleRepository roleRepository;

    public UserController(UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('PERM_read_user')")
    @Operation(summary = "Get All Users", description = "Retrieve all active users (requires read_user permission)")
    @ApiResponse(responseCode = "200", description = "Users retrieved successfully")
    @ApiResponse(responseCode = "403", description = "Access denied - read_user permission required")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_read_user')")
    @Operation(
        summary = "Get User by ID", 
        description = "Retrieve user details by ID (requires read_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "User found")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "403", description = "Access denied - read_user permission required")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/profile")
    @Operation(
        summary = "Get Current User Profile", 
        description = "Get the profile of the currently authenticated user"
    )
    @ApiResponse(responseCode = "200", description = "Profile retrieved successfully")
    @ApiResponse(responseCode = "401", description = "User not authenticated")
    @ApiResponse(responseCode = "404", description = "User profile not found")
    public ResponseEntity<?> getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "User not authenticated"));
        }
        
        String email = authentication.getName();
        Optional<User> user = userService.getUserByEmail(email);
        
        if (user.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        return ResponseEntity.ok(user.get());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('PERM_create_user')")
    @Operation(
        summary = "Create User", 
        description = "Create a new user account (requires create_user permission)",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User creation details",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Create User Example",
                    value = "{\"username\": \"jane.doe\", \"email\": \"jane.doe@bancassurance.com\", \"phoneNumber\": \"+254712345679\", \"password\": \"password123\", \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"roleId\": 2, \"authSource\": \"EMAIL\"}"
                )
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "User created successfully")
    @ApiResponse(responseCode = "400", description = "Invalid input or user already exists")
    @ApiResponse(responseCode = "403", description = "Access denied - create_user permission required")
    public ResponseEntity<?> createUser(@RequestBody Map<String, Object> userRequest) {
        try {
            String username = (String) userRequest.get("username");
            String email = (String) userRequest.get("email");
            String phoneNumber = (String) userRequest.get("phoneNumber");
            String password = (String) userRequest.get("password");
            String firstName = (String) userRequest.get("firstName");
            String lastName = (String) userRequest.get("lastName");
            Long roleId = Long.valueOf(userRequest.get("roleId").toString());
            String authSourceStr = (String) userRequest.get("authSource");
            
            // Validate required fields
            if (username == null || email == null || password == null || roleId == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username, email, password, and roleId are required"));
            }
            
            // Get role
            Optional<Role> roleOptional = roleRepository.findById(roleId);
            if (roleOptional.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role ID"));
            }
            
            AuthenticationSource authSource = AuthenticationSource.EMAIL;
            if (authSourceStr != null) {
                try {
                    authSource = AuthenticationSource.valueOf(authSourceStr.toUpperCase());
                } catch (IllegalArgumentException e) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Invalid authentication source"));
                }
            }
            
            User user = userService.registerUser(username, email, phoneNumber, password, roleOptional.get(), authSource);
            
            // Set additional fields
            if (firstName != null) user.setFirstName(firstName);
            if (lastName != null) user.setLastName(lastName);
            
            user = userService.updateUser(user);
            
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_update_user')")
    @Operation(
        summary = "Update User", 
        description = "Update user details by ID (requires update_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "User updated successfully")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "403", description = "Access denied - update_user permission required")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody Map<String, Object> userDetails) {
        Optional<User> existingUser = userService.getUserById(id);
        
        if (existingUser.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        User user = existingUser.get();
        
        // Update fields
        if (userDetails.containsKey("firstName")) {
            user.setFirstName((String) userDetails.get("firstName"));
        }
        if (userDetails.containsKey("lastName")) {
            user.setLastName((String) userDetails.get("lastName"));
        }
        if (userDetails.containsKey("phoneNumber")) {
            user.setPhoneNumber((String) userDetails.get("phoneNumber"));
        }
        if (userDetails.containsKey("roleId")) {
            Long roleId = Long.valueOf(userDetails.get("roleId").toString());
            Optional<Role> roleOptional = roleRepository.findById(roleId);
            if (roleOptional.isPresent()) {
                user.setRole(roleOptional.get());
            }
        }
        
        return ResponseEntity.ok(userService.updateUser(user));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_delete_user')")
    @Operation(
        summary = "Delete User", 
        description = "Soft delete user by ID (requires delete_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "User deleted successfully")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "403", description = "Access denied - delete_user permission required")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        Optional<User> user = userService.getUserById(id);
        if (user.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        userService.softDeleteUser(id);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAuthority('PERM_read_user')")
    @Operation(
        summary = "Get Pending Users", 
        description = "Get users pending approval (requires read_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "Pending users retrieved successfully")
    @ApiResponse(responseCode = "403", description = "Access denied - read_user permission required")
    public ResponseEntity<List<User>> getPendingUsers() {
        return ResponseEntity.ok(userService.getPendingApprovalUsers());
    }

    @PutMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('PERM_update_user')")
    @Operation(
        summary = "Approve User", 
        description = "Approve pending user account (requires update_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "User approved successfully")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "403", description = "Access denied - update_user permission required")
    public ResponseEntity<?> approveUser(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userService.getCurrentUser(authentication);
        
        userService.approveUser(id, currentUser.getUserId());
        return ResponseEntity.ok(Map.of("message", "User approved successfully"));
    }

    @PutMapping("/{id}/reject")
    @PreAuthorize("hasAuthority('PERM_update_user')")
    @Operation(
        summary = "Reject User", 
        description = "Reject pending user account (requires update_user permission)"
    )
    @ApiResponse(responseCode = "200", description = "User rejected successfully")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "403", description = "Access denied - update_user permission required")
    public ResponseEntity<?> rejectUser(@PathVariable Long id, @RequestBody Map<String, String> rejectionData) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userService.getCurrentUser(authentication);
        
        String reason = rejectionData.get("reason");
        userService.rejectUser(id, currentUser.getUserId(), reason);
        return ResponseEntity.ok(Map.of("message", "User rejected successfully"));
    }

    @PutMapping("/change-password")
    @Operation(
        summary = "Change Password", 
        description = "Change password for the currently authenticated user"
    )
    @ApiResponse(responseCode = "200", description = "Password changed successfully")
    @ApiResponse(responseCode = "401", description = "User not authenticated")
    @ApiResponse(responseCode = "400", description = "Invalid password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordData) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("error", "User not authenticated"));
        }
        
        String email = authentication.getName();
        String newPassword = passwordData.get("newPassword");
        
        if (newPassword == null || newPassword.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password is required"));
        }
        
        try {
            userService.changePassword(email, newPassword);
            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}