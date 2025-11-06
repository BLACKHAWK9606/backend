package com.bancassurance.authentication.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;
    
    // Identity Information
    @Column(name = "username", unique = true, nullable = false, length = 100)
    private String username;
    
    @Column(name = "first_name", length = 100)
    private String firstName;
    
    @Column(name = "last_name", length = 100)
    private String lastName;
    
    @Column(name = "email", unique = true, nullable = false, length = 255)
    private String email;
    
    @Column(name = "phone_number", unique = true, length = 20)
    @Pattern(regexp = "^254[17]\\d{8}$", message = "Phone number must be in Kenyan format: 254XXXXXXXXX")
    private String phoneNumber;
    
    // Authentication
    @Enumerated(EnumType.STRING)
    @Column(name = "authentication_source", length = 20)
    private AuthenticationSource authenticationSource = AuthenticationSource.EMAIL;
    
    @Column(name = "password", length = 255)
    private String password;
    
    @Column(name = "password_reset_token", length = 255)
    private String passwordResetToken;
    
    // Account Status
    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 20)
    private UserStatus status = UserStatus.ACTIVE;
    
    @Column(name = "is_active")
    private Boolean isActive = true;
    
    // Role Assignment
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
    
    // Audit Fields
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "is_logged_in")
    private Boolean isLoggedIn = false;
    
    @Column(name = "is_first_login")
    private Boolean isFirstLogin = true;
    
    @Column(name = "last_login")
    private LocalDateTime lastLogin;
    
    // Lifecycle Management
    @Column(name = "is_deleted")
    private Boolean isDeleted = false;
    
    @Column(name = "is_approved")
    private Boolean isApproved = false;
    
    @Column(name = "approval_timestamp")
    private LocalDateTime approvalTimestamp;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approved_by", nullable = true)
    @JsonIgnore
    private User approvedBy;
    
    @Column(name = "is_rejected")
    private Boolean isRejected = false;
    
    @Column(name = "rejection_timestamp")
    private LocalDateTime rejectionTimestamp;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rejected_by", nullable = true)
    @JsonIgnore
    private User rejectedBy;
    
    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;
    
    // Security Policies
    @Column(name = "remaining_days_till_password_reset")
    private Integer remainingDaysTillPasswordReset = 90;
    
    @Column(name = "has_accepted_terms")
    private Boolean hasAcceptedTerms = false;

    // Security Questions
    @Column(name = "security_questions_set")
    private Boolean securityQuestionsSet = false;
    
    @Column(name = "security_questions_mandatory")
    private Boolean securityQuestionsMandatory = true;
    
    // Phone Verification
    @Column(name = "is_phone_verified")
    private Boolean isPhoneVerified = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonIgnore
    private Set<UserSecurityAnswer> securityAnswers;
    
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}