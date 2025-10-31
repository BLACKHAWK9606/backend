package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.services.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Multi-identifier authentication and password management")
public class AuthController {
    
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    @Operation(
        summary = "Multi-Identifier Login", 
        description = "Authenticate user with email, phone, or AD credentials. Supports 3 authentication types.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Login credentials with authentication type",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Email Login",
                        value = "{\"identifier\": \"user@bancassurance.com\", \"password\": \"password123\", \"authType\": \"EMAIL\"}"
                    ),
                    @ExampleObject(
                        name = "Phone Login", 
                        value = "{\"identifier\": \"+254712345678\", \"password\": \"password123\", \"authType\": \"PHONE\"}"
                    ),
                    @ExampleObject(
                        name = "Active Directory Login",
                        value = "{\"identifier\": \"user@company.local\", \"password\": \"adPassword123\", \"authType\": \"ACTIVE_DIRECTORY\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Login successful", 
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"token\": \"eyJhbGciOiJIUzI1NiJ9...\", \"userId\": \"1\", \"username\": \"john.doe\", \"email\": \"john.doe@bancassurance.com\", \"roleName\": \"POLICY_MANAGER\", \"authSource\": \"DATABASE\"}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid credentials or account issues")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
        try {
            String identifier = loginRequest.get("identifier");
            String password = loginRequest.get("password");
            String authType = loginRequest.get("authType");
            
            if (identifier == null || password == null || authType == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Identifier, password, and authType are required"));
            }
            
            Map<String, Object> response = authService.login(identifier, password, authType);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/forgot-password")
    @Operation(
        summary = "Forgot Password", 
        description = "Generate password reset token for user. Supports email, phone, or username identifier.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User identifier for password reset",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Forgot Password Example",
                    value = "{\"identifier\": \"user@bancassurance.com\"}"
                )
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Reset token generated successfully",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"message\": \"Password reset token generated successfully\", \"token\": \"abc123-def456-ghi789\", \"email\": \"user@bancassurance.com\"}"
            )))
    @ApiResponse(responseCode = "400", description = "User not found or account inactive")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> forgotPasswordRequest) {
        try {
            String identifier = forgotPasswordRequest.get("identifier");
            
            if (identifier == null || identifier.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Identifier is required"));
            }
            
            Map<String, String> response = authService.forgotPassword(identifier);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
    
    @PostMapping("/reset-password")
    @Operation(
        summary = "Reset Password",
        description = "Reset user password using the token received from forgot-password endpoint. Token expires in 24 hours.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Reset token and new password",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Reset Password Example",
                    value = "{\"token\": \"4ac01ef1-037e-4b4e-a349-eb3f6b71dd36\", \"newPassword\": \"NewSecurePassword123!\"}"
                )
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Password reset successful",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                value = "{\"message\": \"Password has been reset successfully\"}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid token, expired token, or missing fields")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> resetPasswordRequest) {
        try {
            String token = resetPasswordRequest.get("token");
            String newPassword = resetPasswordRequest.get("newPassword");
            
            if (token == null || token.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Reset token is required"));
            }
            
            if (newPassword == null || newPassword.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "New password is required"));
            }
            
            Map<String, String> response = authService.resetPassword(token, newPassword);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
    
    @GetMapping("/validate-reset-token")
    @Operation(
        summary = "Validate Reset Token",
        description = "Check if password reset token is valid and not expired. Use this before showing reset password form."
    )
    @ApiResponse(responseCode = "200", description = "Token validation result",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Valid Token",
                    value = "{\"valid\": true}"
                ),
                @ExampleObject(
                    name = "Invalid Token",
                    value = "{\"valid\": false}"
                )
            }))
    public ResponseEntity<?> validateResetToken(@RequestParam String token) {
        try {
            boolean isValid = authService.validateResetToken(token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", isValid);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/auth-types")
    @Operation(
        summary = "Get Authentication Types",
        description = "Get available authentication types for the system"
    )
    @ApiResponse(responseCode = "200", description = "Authentication types retrieved successfully")
    public ResponseEntity<?> getAuthenticationTypes() {
        Map<String, Object> response = new HashMap<>();
        response.put("authTypes", AuthenticationSource.values());
        response.put("descriptions", Map.of(
            "EMAIL", "Email + Password (Local Database)",
            "PHONE", "Phone + Password (Local Database)", 
            "ACTIVE_DIRECTORY", "Domain Email + Password (LDAP)"
        ));
        return ResponseEntity.ok(response);
    }
}