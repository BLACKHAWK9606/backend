package com.bancassurance.authentication.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TempToken {
    
    private String token;
    private Long userId;
    private String purpose; // "LOGIN", "REGISTRATION", "PASSWORD_RESET"
    private LocalDateTime expiresAt;
    private String userEmail;
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}