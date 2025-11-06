package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.TempToken;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TempTokenService {
    
    private final Map<String, TempToken> tempTokens = new ConcurrentHashMap<>();
    
    public String generateTempToken(Long userId, String purpose, String userEmail, int expiryMinutes) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(expiryMinutes);
        
        TempToken tempToken = new TempToken(token, userId, purpose, expiresAt, userEmail);
        tempTokens.put(token, tempToken);
        
        // Cleanup expired tokens
        cleanupExpiredTokens();
        
        return token;
    }
    
    public Optional<TempToken> validateAndConsumeTempToken(String token, String expectedPurpose) {
        TempToken tempToken = tempTokens.get(token);
        
        if (tempToken == null) {
            return Optional.empty();
        }
        
        if (tempToken.isExpired()) {
            tempTokens.remove(token);
            return Optional.empty();
        }
        
        if (!expectedPurpose.equals(tempToken.getPurpose())) {
            return Optional.empty();
        }
        
        // Consume the token (remove it after use)
        tempTokens.remove(token);
        return Optional.of(tempToken);
    }
    
    public void cleanupExpiredTokens() {
        tempTokens.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}