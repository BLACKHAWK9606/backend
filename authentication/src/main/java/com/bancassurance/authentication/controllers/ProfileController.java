package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/profile")
@Tag(name = "Profile Management", description = "User profile viewing and management")
@SecurityRequirement(name = "Bearer Authentication")
public class ProfileController {
    
    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @Operation(
        summary = "Get My Own Profile", 
        description = "Retrieve your own profile information. This endpoint uses your JWT token to identify you automatically. IMPORTANT: Make sure you're authenticated (click Authorize button above and enter your JWT token). This shows your personal account details including role, permissions, and account status."
    )
    @ApiResponse(responseCode = "200", description = "Your profile retrieved successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "Profile Response Example",
                description = "Example of your profile data",
                value = "{\"userId\": 1, \"username\": \"superuser\", \"firstName\": \"System\", \"lastName\": \"Administrator\", \"email\": \"superuser@bancassurance.com\", \"phoneNumber\": \"+1234567890\", \"roleName\": \"SUPER_ADMIN\", \"authenticationSource\": \"EMAIL\", \"isActive\": true, \"isApproved\": true, \"createdAt\": \"2025-10-30T17:11:56.311231\", \"lastLogin\": \"2025-10-31T14:20:32.860861\"}"
            )))
    @ApiResponse(responseCode = "401", description = "Unauthorized - You must be logged in. Click Authorize button and enter your JWT token.")
    public ResponseEntity<?> getMyProfile(Authentication authentication) {
        try {
            String username = authentication.getName();
            Map<String, Object> profile = userService.getUserProfile(username);
            return ResponseEntity.ok(profile);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('SUPER_ADMIN') or hasAuthority('PERM_read_user')")
    @Operation(
        summary = "Get Any User's Profile (Admin Only)", 
        description = "Retrieve profile details of any user by their user ID. This is an administrative function restricted to SUPER_ADMIN role or users with 'read_user' permission. Use this to view other users' profiles for management purposes. To find user IDs, use GET /api/users first."
    )
    @ApiResponse(responseCode = "200", description = "User profile retrieved successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "User Profile Example",
                description = "Example of another user's profile",
                value = "{\"userId\": 3, \"username\": \"sarah.officer\", \"firstName\": \"Sarah\", \"lastName\": \"Johnson\", \"email\": \"sarah.johnson@bancassurance.com\", \"phoneNumber\": \"+1234567892\", \"roleName\": \"CLAIMS_OFFICER\", \"authenticationSource\": \"EMAIL\", \"isActive\": true, \"isApproved\": true, \"createdAt\": \"2025-10-30T17:13:44.335009\"}"
            )))
    @ApiResponse(responseCode = "401", description = "Unauthorized - Missing or invalid JWT token")
    @ApiResponse(responseCode = "403", description = "Forbidden - You need SUPER_ADMIN role or 'read_user' permission")
    @ApiResponse(responseCode = "404", description = "User not found with the specified ID")
    public ResponseEntity<?> getUserProfile(@PathVariable Long userId, Authentication authentication) {
        try {
            String currentUsername = authentication.getName();
            Map<String, Object> profile = userService.getUserProfileById(userId, currentUsername);
            return ResponseEntity.ok(profile);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/search")
    @PreAuthorize("hasRole('SUPER_ADMIN') or hasAuthority('PERM_read_user')")
    @Operation(
        summary = "Search User Profiles (Admin Only)", 
        description = "Search for users by email, phone number, or username. Administrative function for SUPER_ADMIN or users with 'read_user' permission. Provide one search parameter - if no parameters are provided, returns all active users. Use this to find specific users before viewing their detailed profiles."
    )
    @ApiResponse(responseCode = "200", description = "Search results retrieved successfully",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Search Results Example",
                    description = "Example search results with user count",
                    value = "{\"users\": [{\"userId\": 2, \"username\": \"john.manager\", \"firstName\": \"John\", \"lastName\": \"Smith\", \"email\": \"john.smith@bancassurance.com\", \"roleName\": \"POLICY_MANAGER\"}], \"count\": 1}"
                ),
                @ExampleObject(
                    name = "All Users Result",
                    description = "When no search parameters provided",
                    value = "{\"users\": [{\"userId\": 1, \"username\": \"superuser\"}, {\"userId\": 2, \"username\": \"john.manager\"}], \"count\": 2}"
                )
            }))
    @ApiResponse(responseCode = "401", description = "Unauthorized - Missing or invalid JWT token")
    @ApiResponse(responseCode = "403", description = "Forbidden - You need SUPER_ADMIN role or 'read_user' permission")
    public ResponseEntity<?> searchUsers(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String phone,
            @RequestParam(required = false) String username,
            Authentication authentication) {
        try {
            String currentUsername = authentication.getName();
            Map<String, Object> results = userService.searchUsers(email, phone, username, currentUsername);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
}