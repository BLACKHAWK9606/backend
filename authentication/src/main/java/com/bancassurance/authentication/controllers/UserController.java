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
        summary = "Update User Details", 
        description = "Update specific user details by user ID. Only administrators with 'update_user' permission can modify user information. You can update firstName, lastName, phoneNumber, and roleId. Only include the fields you want to change - partial updates are supported.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "JSON object containing the fields to update. Available fields: firstName, lastName, phoneNumber, roleId. Phone numbers must be in Kenyan format (+254XXXXXXXXX). Role IDs: 1=SUPER_ADMIN, 2=POLICY_MANAGER, 3=CLAIMS_OFFICER, 4=VIEWER",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Update Name and Phone",
                        description = "Update user's name and phone number only",
                        value = "{\"firstName\": \"UpdatedFirstName\", \"lastName\": \"UpdatedLastName\", \"phoneNumber\": \"+254712345999\"}"
                    ),
                    @ExampleObject(
                        name = "Change User Role",
                        description = "Promote/demote user by changing their role",
                        value = "{\"roleId\": 3}"
                    ),
                    @ExampleObject(
                        name = "Complete Profile Update",
                        description = "Update all modifiable user fields at once",
                        value = "{\"firstName\": \"John\", \"lastName\": \"Doe\", \"phoneNumber\": \"+254712345888\", \"roleId\": 2}"
                    )
                }
            )
        )
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
        // Handle both roleId and role_id for flexibility
        if (userDetails.containsKey("roleId") || userDetails.containsKey("role_id")) {
            Object roleIdObj = userDetails.containsKey("roleId") ? userDetails.get("roleId") : userDetails.get("role_id");
            Long roleId = Long.valueOf(roleIdObj.toString());
            Optional<Role> roleOptional = roleRepository.findById(roleId);
            if (roleOptional.isPresent()) {
                user.setRole(roleOptional.get());
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role ID: " + roleId));
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
        summary = "Reject Pending User Account", 
        description = "Reject a user account that is pending approval. This action requires 'update_user' permission and can only be performed on users with isApproved=false. The rejection reason will be stored and the user will be marked as rejected. Use GET /api/users/pending to see users awaiting approval first.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "JSON object containing the rejection reason. The 'reason' field is required and will be stored in the user's record for audit purposes.",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Documentation Issue",
                        description = "Reject due to incomplete or invalid documentation",
                        value = "{\"reason\": \"Incomplete documentation provided - missing ID verification\"}"
                    ),
                    @ExampleObject(
                        name = "Policy Violation",
                        description = "Reject due to company policy non-compliance",
                        value = "{\"reason\": \"Does not meet company policy requirements for external contractors\"}"
                    ),
                    @ExampleObject(
                        name = "Duplicate Account",
                        description = "Reject due to existing account",
                        value = "{\"reason\": \"User already has an existing active account in the system\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "User rejected successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"message\": \"User rejected successfully\"}"
            )))
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
        summary = "Change Own Password", 
        description = "Change password for the currently authenticated user. This endpoint is for users who are already logged in and want to update their password. IMPORTANT: You must be authenticated with a valid JWT token (use the Authorize button above). This is different from password reset - use this when you know your current password and want to change it.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "JSON object containing the new password. Password should be strong (minimum 8 characters, include uppercase, lowercase, numbers, and special characters). The system will automatically identify the user from the JWT token.",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Strong Password Example",
                        description = "Example of a secure password meeting all requirements",
                        value = "{\"newPassword\": \"MyNewSecurePassword123!\"}"
                    ),
                    @ExampleObject(
                        name = "Alternative Format",
                        description = "Another example of a valid strong password",
                        value = "{\"newPassword\": \"BancAssur@2024#Safe\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Password changed successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"message\": \"Password changed successfully\"}"
            )))
    @ApiResponse(responseCode = "401", description = "User not authenticated")
    @ApiResponse(responseCode = "400", description = "Invalid password or missing newPassword field")
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