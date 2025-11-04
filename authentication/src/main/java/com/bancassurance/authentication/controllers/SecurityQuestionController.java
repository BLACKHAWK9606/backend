package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.SecurityAnswerRequest;
import com.bancassurance.authentication.models.SecurityQuestion;
import com.bancassurance.authentication.services.SecurityQuestionService;
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
@RequestMapping("/auth/security-questions")
@Tag(name = "Security Questions", description = "Security questions management for password recovery")
public class SecurityQuestionController {
    
    private final SecurityQuestionService securityQuestionService;
    
    public SecurityQuestionController(SecurityQuestionService securityQuestionService) {
        this.securityQuestionService = securityQuestionService;
    }
    
    @GetMapping("/available")
    @Operation(
        summary = "Get Available Security Questions", 
        description = "Retrieve the complete list of available security questions that users can choose from when setting up their account security. This endpoint should be called before /auth/security-questions/setup to show users their options. Questions are pre-configured by administrators and cover common personal information categories.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Available security questions retrieved successfully",
                content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Available Questions Response",
                        description = "List of all active security questions with setup requirements",
                        value = "{\"questions\": [{\"id\": 1, \"text\": \"What was your first pet's name?\"}, {\"id\": 2, \"text\": \"In what city were you born?\"}, {\"id\": 3, \"text\": \"What is your mother's maiden name?\"}, {\"id\": 4, \"text\": \"What was the make of your first car?\"}, {\"id\": 5, \"text\": \"What elementary school did you attend?\"}], \"minimumRequired\": 3, \"maximumAllowed\": 5, \"totalAvailable\": 10}"
                    )))
        }
    )
    public ResponseEntity<?> getAvailableQuestions() {
        try {
            List<SecurityQuestion> questions = securityQuestionService.getActiveQuestions();
            
            Map<String, Object> response = new HashMap<>();
            response.put("questions", questions.stream().map(q -> Map.of(
                "id", q.getQuestionId(),
                "text", q.getQuestionText()
            )).toList());
            response.put("minimumRequired", 3);
            response.put("maximumAllowed", 5);
            response.put("totalAvailable", questions.size());
            response.put("instructions", "Select " + 3 + "-" + 5 + " questions and provide answers of at least 3 characters each");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/setup")
    @Operation(
        summary = "Setup Security Questions", 
        description = "Setup security questions for a user account. This endpoint is used after user registration to configure security questions for password recovery. Users must select 3-5 questions from the available list and provide answers. All answers are encrypted and stored securely. This is typically called immediately after user account creation when 'requiresSecuritySetup' is true.",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Security questions setup request containing userId and array of question-answer pairs. Get available questions from /auth/security-questions/available first.",
            content = @Content(
                mediaType = "application/json",
                examples = {
                    @ExampleObject(
                        name = "Minimum Setup (3 questions)",
                        description = "Setup with minimum required 3 security questions",
                        value = "{\"userId\": 101, \"answers\": [{\"questionId\": 1, \"answer\": \"Fluffy\"}, {\"questionId\": 3, \"answer\": \"Johnson\"}, {\"questionId\": 5, \"answer\": \"Lincoln Elementary\"}]}"
                    ),
                    @ExampleObject(
                        name = "Full Setup (5 questions)",
                        description = "Setup with maximum allowed 5 security questions for enhanced security",
                        value = "{\"userId\": 101, \"answers\": [{\"questionId\": 1, \"answer\": \"Fluffy\"}, {\"questionId\": 2, \"answer\": \"Nairobi\"}, {\"questionId\": 3, \"answer\": \"Johnson\"}, {\"questionId\": 4, \"answer\": \"Toyota Corolla\"}, {\"questionId\": 5, \"answer\": \"Lincoln Elementary\"}]}"
                    ),
                    @ExampleObject(
                        name = "Real World Example",
                        description = "Practical example with realistic answers",
                        value = "{\"userId\": 205, \"answers\": [{\"questionId\": 1, \"answer\": \"Max\"}, {\"questionId\": 7, \"answer\": \"Mombasa\"}, {\"questionId\": 8, \"answer\": \"Sarah\"}, {\"questionId\": 10, \"answer\": \"Champ\"}]}"
                    )
                }
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Security questions setup successful",
        content = @Content(mediaType = "application/json",
            examples = @ExampleObject(
                name = "Setup Success Response",
                description = "Confirmation that security questions have been configured",
                value = "{\"message\": \"Security questions set successfully\", \"questionsCount\": 3, \"accountStatus\": \"active\", \"securityQuestionsSet\": true}"
            )))
    @ApiResponse(responseCode = "400", description = "Invalid request - Validation errors",
        content = @Content(mediaType = "application/json",
            examples = {
                @ExampleObject(
                    name = "Too Few Questions",
                    description = "Less than 3 questions provided",
                    value = "{\"error\": \"Must provide between 3 and 5 security questions\"}"
                ),
                @ExampleObject(
                    name = "Duplicate Questions",
                    description = "Same question selected multiple times",
                    value = "{\"error\": \"Duplicate questions not allowed\"}"
                ),
                @ExampleObject(
                    name = "Short Answer",
                    description = "Answer too short (less than 3 characters)",
                    value = "{\"error\": \"Each answer must be at least 3 characters\"}"
                ),
                @ExampleObject(
                    name = "Invalid Question ID",
                    description = "Question ID does not exist",
                    value = "{\"error\": \"Invalid question ID: 99\"}"
                )
            }))
    @ApiResponse(responseCode = "404", description = "User not found with provided userId")
    public ResponseEntity<?> setupSecurityQuestions(@RequestBody Map<String, Object> request) {
        try {
            Long userId = Long.valueOf(request.get("userId").toString());
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> answersData = (List<Map<String, Object>>) request.get("answers");
            
            List<SecurityAnswerRequest> answers = answersData.stream()
                .map(data -> new SecurityAnswerRequest(
                    Long.valueOf(data.get("questionId").toString()),
                    data.get("answer").toString()
                )).toList();
            
            securityQuestionService.setUserSecurityAnswers(userId, answers);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Security questions set successfully");
            response.put("questionsCount", answers.size());
            response.put("accountStatus", "active");
            response.put("securityQuestionsSet", true);
            response.put("canUseSecureReset", true);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @GetMapping("/status/{userId}")
    @Operation(
        summary = "Check Security Questions Status", 
        description = "Check whether a specific user has completed their security questions setup. This endpoint is useful for determining if a user needs to be redirected to the security questions setup page or if they can proceed with password reset using security questions. Returns the current status and user information.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Security questions status retrieved successfully",
                content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(
                            name = "Questions Configured",
                            description = "User has completed security questions setup",
                            value = "{\"securityQuestionsSet\": true, \"userId\": 101, \"questionsCount\": 3, \"canUseSecureReset\": true}"
                        ),
                        @ExampleObject(
                            name = "Questions Not Configured",
                            description = "User has not set up security questions yet",
                            value = "{\"securityQuestionsSet\": false, \"userId\": 101, \"questionsCount\": 0, \"canUseSecureReset\": false, \"setupRequired\": true}"
                        )
                    }))
        }
    )
    public ResponseEntity<?> getSecurityQuestionsStatus(@PathVariable Long userId) {
        try {
            boolean hasQuestions = securityQuestionService.hasSecurityQuestionsSet(userId);
            
            long questionsCount = securityQuestionService.hasSecurityQuestionsSet(userId) ? 
                securityQuestionService.getUserSecurityQuestions(userId).size() : 0;
            
            Map<String, Object> response = new HashMap<>();
            response.put("securityQuestionsSet", hasQuestions);
            response.put("userId", userId);
            response.put("questionsCount", questionsCount);
            response.put("canUseSecureReset", hasQuestions);
            if (!hasQuestions) {
                response.put("setupRequired", true);
                response.put("setupEndpoint", "/auth/security-questions/setup");
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}