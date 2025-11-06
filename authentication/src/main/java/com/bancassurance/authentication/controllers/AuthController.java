package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.AuthenticationSource;
import com.bancassurance.authentication.models.SecurityAnswerRequest;
import com.bancassurance.authentication.models.OtpVerificationRequest;
import com.bancassurance.authentication.models.ResetOtpVerificationRequest;
import com.bancassurance.authentication.services.AuthService;
import com.bancassurance.authentication.services.TwoFactorService;
import com.bancassurance.authentication.services.PasswordResetService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@Tag(name = "Authentication", description = "Multi-identifier authentication and password management")
public class AuthController {
    
    private final AuthService authService;
    private final TwoFactorService twoFactorService;
    private final PasswordResetService passwordResetService;

    public AuthController(AuthService authService, TwoFactorService twoFactorService, 
                         PasswordResetService passwordResetService) {
        this.authService = authService;
        this.twoFactorService = twoFactorService;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/login")
    @Operation(
        summary = "Multi-Identifier Login with 2FA", 
        description = "Authenticate user credentials and initiate 2FA process. No JWT tokens are issued at this stage - tokens are only issued after OTP verification.",
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
    @ApiResponse(responseCode = "200", description = "Credentials validated - OTP sent for verification", 
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "2FA Required Response",
                description = "Credentials valid, OTP sent to phone, temporary token issued",
                value = "{\"requiresOtp\": true, \"tempToken\": \"temp_abc123\", \"otpMethod\": \"SMS\", \"message\": \"OTP sent to your registered phone number\", \"expiresIn\": 300}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid credentials, account issues, or authentication source mismatch")
    @ApiResponse(responseCode = "401", description = "Authentication failed - Invalid password or user not found")
    @ApiResponse(responseCode = "403", description = "Account access denied - User account is deactivated, deleted, pending approval, or rejected")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginRequest) {
        try {
            String identifier = loginRequest.get("identifier");
            String password = loginRequest.get("password");
            String authType = loginRequest.get("authType");
            
            if (identifier == null || password == null || authType == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Identifier, password, and authType are required"));
            }
            
            // Validate credentials using existing AuthService logic
            Map<String, Object> authResult = authService.validateCredentialsOnly(identifier, password, authType);
            
            // If credentials are valid, initiate 2FA
            if (authResult.containsKey("user")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> userMap = (Map<String, Object>) authResult.get("user");
                
                // Create a minimal User object for 2FA
                com.bancassurance.authentication.models.User user = new com.bancassurance.authentication.models.User();
                user.setUserId(Long.valueOf(userMap.get("userId").toString()));
                user.setEmail(userMap.get("email").toString());
                user.setPhoneNumber(userMap.get("phoneNumber").toString());
                
                Map<String, Object> response = twoFactorService.initiate2FA(user);
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "Authentication failed"));
            }
            
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/verify-login-otp")
    @Operation(
        summary = "Verify Login OTP and Issue JWT Tokens", 
        description = "Verify the OTP code sent during login and issue JWT access and refresh tokens. This is where actual authentication tokens are generated after successful 2FA verification.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Temporary token from login and OTP code from SMS",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "OTP Verification",
                        value = "{\"tempToken\": \"temp_abc123\", \"otpCode\": \"123456\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "OTP verified successfully - JWT tokens issued", 
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "Successful Login Response",
                description = "Login completed with access token (15 min) and refresh token (2 hours)",
                value = "{\"accessToken\": \"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.abc123\", \"refreshToken\": \"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjF9.xyz789\", \"tokenType\": \"Bearer\", \"expiresIn\": 900, \"userId\": \"1\", \"username\": \"superuser\", \"email\": \"superuser@bancassurance.com\", \"roleName\": \"SUPER_ADMIN\", \"isFirstLogin\": false, \"authSource\": \"EMAIL\"}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid OTP code, expired temporary token, or verification failed")
    @ApiResponse(responseCode = "401", description = "OTP verification failed - Invalid or expired code")
    public ResponseEntity<?> verifyLoginOtp(@RequestBody OtpVerificationRequest request) {
        try {
            if (request.getTempToken() == null || request.getOtpCode() == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Temporary token and OTP code are required"));
            }
            
            Map<String, Object> response = twoFactorService.verifyOtpAndIssueTokens(
                request.getTempToken(), 
                request.getOtpCode()
            );
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/forgot-password")
    @Operation(
        summary = "Forgot Password with OTP Verification", 
        description = "Initiate password reset process with OTP verification. This endpoint now requires OTP verification before proceeding to security questions or password reset.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User identifier (email, phone number, or username) for password reset initiation",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Email Identifier",
                        description = "Reset password using email address",
                        value = "{\"identifier\": \"user@bancassurance.com\"}"
                    ),
                    @ExampleObject(
                        name = "Phone Identifier",
                        description = "Reset password using phone number",
                        value = "{\"identifier\": \"+254712345678\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "OTP sent for identity verification",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "OTP Verification Required",
                description = "OTP sent to phone for identity verification before password reset",
                value = "{\"requiresOtpVerification\": true, \"tempResetToken\": \"temp_reset_abc123\", \"otpMethod\": \"SMS\", \"message\": \"OTP sent to your registered phone number for identity verification\", \"expiresIn\": 900}"
            )))
    @ApiResponse(responseCode = "400", description = "User not found, account inactive, or invalid identifier")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> forgotPasswordRequest) {
        try {
            String identifier = forgotPasswordRequest.get("identifier");
            
            if (identifier == null || identifier.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Identifier is required"));
            }
            
            Map<String, Object> response = passwordResetService.initiatePasswordResetWithOtp(identifier);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PostMapping("/verify-reset-otp")
    @Operation(
        summary = "Verify Password Reset OTP", 
        description = "Verify the OTP sent during password reset and proceed to security questions or direct password reset.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Temporary reset token from forgot-password and OTP code from SMS",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Reset OTP Verification",
                        value = "{\"tempResetToken\": \"temp_reset_abc123\", \"otpCode\": \"123456\"}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "OTP verified successfully - Proceed to security questions or password reset", 
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Security Questions Required",
                    description = "OTP verified, now answer security questions",
                    value = "{\"verified\": true, \"message\": \"OTP verified successfully. Please answer your security questions to proceed\", \"questions\": [{\"id\": 1, \"text\": \"What was your first pet's name?\"}], \"requiresSecurityVerification\": true, \"identifier\": \"user@example.com\"}"
                ),
                @ExampleObject(
                    name = "Direct Password Reset",
                    description = "OTP verified, proceed directly to password reset",
                    value = "{\"verified\": true, \"message\": \"OTP verified successfully. You can now reset your password\", \"passwordResetToken\": \"reset_token_456\", \"requiresSecurityVerification\": false}"
                )
            }))
    @ApiResponse(responseCode = "400", description = "Invalid OTP code, expired temporary token, or verification failed")
    public ResponseEntity<?> verifyResetOtp(@RequestBody ResetOtpVerificationRequest request) {
        try {
            if (request.getTempResetToken() == null || request.getOtpCode() == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Temporary reset token and OTP code are required"));
            }
            
            Map<String, Object> response = passwordResetService.verifyResetOtpAndGetSecurityQuestions(
                request.getTempResetToken(), 
                request.getOtpCode()
            );
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
    
    @PostMapping("/verify-security-answers")
    @Operation(
        summary = "Verify Security Answers", 
        description = "Verify security question answers for password reset. This endpoint is used after /auth/forgot-password returns security questions. You must provide the identifier (email/phone/username) and answer all the security questions correctly. Upon successful verification, you'll receive a passwordResetToken that can be used with /auth/reset-password to complete the password reset process.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Security answers verification request containing the user identifier and answers to all security questions",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Security Answers Verification",
                        description = "Example of verifying security question answers",
                        value = "{\"identifier\": \"john@bancassurance.com\", \"answers\": [{\"questionId\": 1, \"answer\": \"fluffy\"}, {\"questionId\": 3, \"answer\": \"johnson\"}, {\"questionId\": 5, \"answer\": \"lincoln elementary\"}]}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Security answers verified successfully - Password reset token generated",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Verification Successful",
                    description = "All security answers were correct - proceed to reset password",
                    value = "{\"verified\": true, \"message\": \"Security questions verified successfully\", \"passwordResetToken\": \"secure_password_reset_token_456\", \"tokenExpiresIn\": 900}"
                ),
                @ExampleObject(
                    name = "Verification Failed",
                    description = "One or more security answers were incorrect",
                    value = "{\"verified\": false, \"message\": \"One or more security answers are incorrect\", \"attemptsRemaining\": 2, \"lockoutWarning\": \"Account will be temporarily locked after 3 failed attempts\"}"
                )
            }))
    @ApiResponse(responseCode = "400", description = "Invalid request - Missing identifier/answers or user not found")
    @ApiResponse(responseCode = "423", description = "Account temporarily locked due to too many failed verification attempts")
    public ResponseEntity<?> verifySecurityAnswers(@RequestBody Map<String, Object> request) {
        try {
            String identifier = (String) request.get("identifier");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> answersData = (List<Map<String, Object>>) request.get("answers");
            
            if (identifier == null || answersData == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Identifier and answers are required"));
            }
            
            List<SecurityAnswerRequest> answers = answersData.stream()
                .map(data -> new SecurityAnswerRequest(
                    Long.valueOf(data.get("questionId").toString()),
                    data.get("answer").toString()
                )).toList();
            
            Map<String, Object> response = authService.verifySecurityAnswers(identifier, answers);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/reset-password")
    @Operation(
        summary = "Reset Password - Enhanced for Security Questions Flow",
        description = "Reset user password using either: 1) Traditional reset token from forgot-password (24-hour expiry), or 2) Security-verified token from verify-security-answers (15-minute expiry). This endpoint now supports both flows seamlessly. For security questions flow, use the passwordResetToken received from verify-security-answers. For traditional flow, use the token directly from forgot-password.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Reset token (from forgot-password or verify-security-answers) and new password",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Security Questions Flow",
                        description = "Reset password after security questions verification",
                        value = "{\"token\": \"secure_password_reset_token_456\", \"newPassword\": \"NewSecurePassword123!\"}"
                    ),
                    @ExampleObject(
                        name = "Traditional Flow",
                        description = "Reset password with traditional token",
                        value = "{\"token\": \"4ac01ef1-037e-4b4e-a349-eb3f6b71dd36\", \"newPassword\": \"NewSecurePassword123!\"}"
                    )
                }
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

    @PostMapping("/logout")
    @Operation(
        summary = "Logout User - Invalidate Tokens",
        description = "Securely logout user by immediately blacklisting both access and refresh tokens. This endpoint ensures complete session termination for banking security. IMPORTANT: You must be authenticated with a valid JWT token (use the Authorize button above and enter your access token). Once logged out, both your access token and refresh token become permanently invalid and cannot be used for any API calls. This is critical for banking applications to prevent unauthorized access after logout. Optional: Include refreshToken in request body for complete logout."
    )
    @ApiResponse(responseCode = "200", description = "Logout successful - All specified tokens have been blacklisted")
    @ApiResponse(responseCode = "400", description = "Invalid request - Missing or malformed Authorization header")
    @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or expired access token")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader,
                                   @RequestBody(required = false) Map<String, String> logoutRequest) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid authorization header"));
            }
            
            String accessToken = authHeader.substring(7);
            authService.logout(accessToken, logoutRequest != null ? logoutRequest.get("refreshToken") : null);
            
            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/refresh")
    @Operation(
        summary = "Refresh Access Token - Extend Session",
        description = "Generate new access and refresh tokens using your current refresh token. This endpoint allows users to maintain their session without re-entering credentials when their 15-minute access token expires. CRITICAL: This implements token rotation security - your old refresh token will be invalidated and you'll receive new tokens. Store both new tokens securely. This is essential for banking applications to maintain security while providing good user experience. The new access token is valid for 15 minutes, and the new refresh token is valid for 2 hours from the time of this request. Request body should contain: {refreshToken: 'your_refresh_token_here'}"
    )
    @ApiResponse(responseCode = "200", description = "Tokens refreshed successfully - New access and refresh tokens generated")
    @ApiResponse(responseCode = "400", description = "Bad request - Missing refresh token, invalid token format, or token has been used before")
    @ApiResponse(responseCode = "401", description = "Unauthorized - Refresh token is expired, blacklisted, or invalid")
    @ApiResponse(responseCode = "403", description = "Forbidden - User account is inactive, deleted, or not approved")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> refreshRequest) {
        try {
            String refreshToken = refreshRequest.get("refreshToken");
            if (refreshToken == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Refresh token is required"));
            }
            
            Map<String, Object> response = authService.refreshToken(refreshToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
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