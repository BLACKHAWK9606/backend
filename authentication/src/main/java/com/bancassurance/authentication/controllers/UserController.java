package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.models.PhoneVerificationRequest;
import com.bancassurance.authentication.services.UserService;
import com.bancassurance.authentication.services.PhoneVerificationService;
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
    private final PhoneVerificationService phoneVerificationService;
    private final com.bancassurance.authentication.services.OtpService otpService;

    public UserController(UserService userService, RoleRepository roleRepository, 
                         PhoneVerificationService phoneVerificationService,
                         com.bancassurance.authentication.services.OtpService otpService) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.phoneVerificationService = phoneVerificationService;
        this.otpService = otpService;
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
        summary = "Create New User Account", 
        description = "Create a new user account immediately in the system with phone verification pending. This endpoint creates the user record in the database with is_phone_verified set to false. After successful user creation, use the /send-phone-verification endpoint to initiate phone number verification. Requires 'create_user' permission. All required fields must be provided and email/phone must be unique.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Complete user registration details. Phone numbers must be in Kenyan format (254XXXXXXXXX) without + prefix. Role IDs: 1=SUPERUSER, 2=POLICY_MANAGER, 3=CLAIMS_OFFICER, 4=VIEWER. Authentication sources: EMAIL, PHONE, ACTIVE_DIRECTORY.",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Complete User Creation",
                        value = "{\"username\": \"jane.doe\", \"email\": \"jane.doe@bancassurance.com\", \"phoneNumber\": \"254712345679\", \"password\": \"password123\", \"firstName\": \"Jane\", \"lastName\": \"Doe\", \"roleId\": 2, \"authSource\": \"EMAIL\"}"
                    ),
                    @ExampleObject(
                        name = "Minimal User Creation",
                        value = "{\"username\": \"john.smith\", \"email\": \"john.smith@bancassurance.com\", \"phoneNumber\": \"254701234567\", \"password\": \"securePass123\", \"roleId\": 4}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "User account created successfully - Phone verification required",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "User Created Successfully",
                value = "{\"message\": \"User created successfully. Phone verification required.\", \"userId\": 123, \"requiresPhoneVerification\": true, \"isPhoneVerified\": false}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid input data, validation failed, or duplicate email/phone",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Missing Required Fields",
                    value = "{\"error\": \"Username, email, phoneNumber, password, and roleId are required\"}"
                ),
                @ExampleObject(
                    name = "Duplicate Email",
                    value = "{\"error\": \"Email already exists\"}"
                ),
                @ExampleObject(
                    name = "Invalid Role ID",
                    value = "{\"error\": \"Invalid role ID\"}"
                )
            }))
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
            if (username == null || email == null || phoneNumber == null || password == null || roleId == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Username, email, phoneNumber, password, and roleId are required"));
            }
            
            // Get role to validate it exists
            Optional<Role> roleOptional = roleRepository.findById(roleId);
            if (roleOptional.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role ID"));
            }
            
            // Validate authentication source
            AuthenticationSource authSource = AuthenticationSource.EMAIL;
            if (authSourceStr != null) {
                try {
                    authSource = AuthenticationSource.valueOf(authSourceStr.toUpperCase());
                } catch (IllegalArgumentException e) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Invalid authentication source"));
                }
            }
            
            // Check for existing users
            if (userService.getUserByEmail(email).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Email already exists"));
            }
            
            if (userService.getUserByPhoneNumber(phoneNumber).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Phone number already exists"));
            }
            
            // Create user immediately with is_phone_verified = false
            User user = userService.registerUser(username, email, phoneNumber, password, roleOptional.get(), authSource);
            if (firstName != null) user.setFirstName(firstName);
            if (lastName != null) user.setLastName(lastName);
            user.setIsPhoneVerified(false);
            user = userService.updateUser(user);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User created successfully. Phone verification required.");
            response.put("userId", user.getUserId());
            response.put("requiresPhoneVerification", true);
            response.put("isPhoneVerified", false);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/{id}/send-phone-verification")
    @PreAuthorize("hasAuthority('PERM_create_user')")
    @Operation(
        summary = "Send Phone Verification OTP to Existing User", 
        description = "Send SMS OTP to an existing user's registered phone number for phone verification. This endpoint is used after user creation to initiate phone number verification process. The user must exist in the system and their phone must not be already verified. Requires 'create_user' permission. The OTP will be valid for 10 minutes and allows maximum 3 verification attempts."
    )
    @ApiResponse(responseCode = "200", description = "OTP sent successfully to user's phone number",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "OTP Sent Successfully",
                value = "{\"message\": \"OTP sent to phone number\", \"phoneNumber\": \"254712345670\"}"
            )))
    @ApiResponse(responseCode = "404", description = "User not found with the provided ID")
    @ApiResponse(responseCode = "400", description = "Phone number already verified",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "Phone Already Verified",
                value = "{\"error\": \"Phone number already verified\"}"
            )))
    @ApiResponse(responseCode = "403", description = "Access denied - create_user permission required")
    public ResponseEntity<?> sendPhoneVerification(@PathVariable Long id) {
        try {
            Optional<User> userOpt = userService.getUserById(id);
            if (userOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            User user = userOpt.get();
            if (user.getIsPhoneVerified()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Phone number already verified"));
            }
            
            // Send OTP using existing user
            otpService.generateAndSendOtp(user, com.bancassurance.authentication.models.OtpPurpose.PHONE_VERIFICATION);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "OTP sent to phone number");
            response.put("phoneNumber", user.getPhoneNumber());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/{id}/verify-phone")
    @PreAuthorize("hasAuthority('PERM_create_user')")
    @Operation(
        summary = "Verify Phone Number with OTP Code", 
        description = "Verify the SMS OTP code sent to user's phone number and mark the phone as verified in the system. This endpoint completes the phone verification process. Upon successful verification, the user's is_phone_verified field will be set to true. The OTP code must be entered within 10 minutes and users have maximum 3 attempts. Requires 'create_user' permission.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "JSON object containing the 6-digit OTP code received via SMS",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Valid OTP Verification",
                        value = "{\"otpCode\": \"123456\"}"
                    ),
                    @ExampleObject(
                        name = "Alternative OTP Format",
                        value = "{\"otpCode\": \"987654\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Phone number verified successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "Verification Successful",
                value = "{\"message\": \"Phone number verified successfully\", \"isPhoneVerified\": true, \"userId\": 123}"
            )))
    @ApiResponse(responseCode = "404", description = "User not found with the provided ID")
    @ApiResponse(responseCode = "400", description = "Invalid OTP code, expired OTP, or maximum attempts exceeded",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Invalid OTP Code",
                    value = "{\"error\": \"Invalid or expired OTP code\"}"
                ),
                @ExampleObject(
                    name = "Missing OTP Code",
                    value = "{\"error\": \"OTP code is required\"}"
                )
            }))
    @ApiResponse(responseCode = "403", description = "Access denied - create_user permission required")
    public ResponseEntity<?> verifyPhone(@PathVariable Long id, @RequestBody Map<String, String> request) {
        try {
            String otpCode = request.get("otpCode");
            if (otpCode == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "OTP code is required"));
            }
            
            Optional<User> userOpt = userService.getUserById(id);
            if (userOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            User user = userOpt.get();
            
            // Validate OTP
            boolean otpValid = otpService.validateOtp(user.getUserId(), otpCode, com.bancassurance.authentication.models.OtpPurpose.PHONE_VERIFICATION);
            
            if (!otpValid) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired OTP code"));
            }
            
            // Mark phone as verified
            user.setIsPhoneVerified(true);
            userService.updateUser(user);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Phone number verified successfully");
            response.put("isPhoneVerified", true);
            response.put("userId", user.getUserId());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_update_user')")
    @Operation(
        summary = "Update User Details", 
        description = "Update specific user details by user ID. Only administrators with 'update_user' permission can modify user information. You can update firstName, lastName, phoneNumber, roleId, and authentication_source. Only include the fields you want to change - partial updates are supported.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "JSON object containing the fields to update. Available fields: firstName, lastName, phoneNumber, roleId, authentication_source. Phone numbers must be in Kenyan format (+254XXXXXXXXX). Role IDs: 1=SUPER_ADMIN, 2=POLICY_MANAGER, 3=CLAIMS_OFFICER, 4=VIEWER. Authentication sources: EMAIL, PHONE, ACTIVE_DIRECTORY",
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
                    ),
                    @ExampleObject(
                        name = "Change Authentication Source",
                        description = "Update user's authentication method",
                        value = "{\"authentication_source\": \"PHONE\"}"
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
        // Handle authentication source update
        if (userDetails.containsKey("authentication_source") || userDetails.containsKey("authSource")) {
            String authSourceStr = (String) (userDetails.containsKey("authentication_source") ? 
                userDetails.get("authentication_source") : userDetails.get("authSource"));
            try {
                AuthenticationSource authSource = AuthenticationSource.valueOf(authSourceStr.toUpperCase());
                user.setAuthenticationSource(authSource);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid authentication source: " + authSourceStr + ". Valid values: EMAIL, PHONE, ACTIVE_DIRECTORY"));
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