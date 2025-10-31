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
@SecurityRequirement(name = "bearerAuth")
public class ProfileController {
    
    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @Operation(
        summary = "Get My Profile", 
        description = "Get the profile details of the currently logged-in user. Requires valid JWT token."
    )
    @ApiResponse(responseCode = "200", description = "Profile retrieved successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"userId\": \"1\", \"username\": \"superuser\", \"firstName\": \"System\", \"lastName\": \"Administrator\", \"email\": \"superuser@bancassurance.com\", \"phoneNumber\": \"+1234567890\", \"roleName\": \"SUPER_ADMIN\", \"isActive\": true, \"createdAt\": \"2025-10-30T17:11:56.311231\"}"
            )))
    @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")
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
        summary = "Get User Profile by ID (Admin Only)", 
        description = "Get profile details of any user by their ID. Only accessible by superuser/admin roles."
    )
    @ApiResponse(responseCode = "200", description = "User profile retrieved successfully")
    @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")
    @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    @ApiResponse(responseCode = "404", description = "User not found")
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
        description = "Search for users by email, phone, or username. Only accessible by superuser/admin roles."
    )
    @ApiResponse(responseCode = "200", description = "Search results retrieved successfully")
    @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT token")
    @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
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