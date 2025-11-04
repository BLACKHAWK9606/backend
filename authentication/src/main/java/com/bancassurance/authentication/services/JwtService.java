package com.bancassurance.authentication.services;

import com.bancassurance.authentication.config.JwtProperties;
import com.bancassurance.authentication.models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }
    
    public String generateAccessToken(User user) {
        return generateToken(user, jwtProperties.getAccessTokenExpiration(), "access");
    }
    
    public String generateRefreshToken(User user) {
        return generateToken(user, jwtProperties.getRefreshTokenExpiration(), "refresh");
    }
    
    private String generateToken(User user, long expiration, String tokenType) {
        Key key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getUserId());
        claims.put("username", user.getUsername());
        claims.put("roleName", user.getRole().getRoleName());
        claims.put("roleId", user.getRole().getRoleId());
        claims.put("authSource", user.getAuthenticationSource().toString());
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("tokenType", tokenType);
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    public String extractRoleName(String token) {
        return extractClaim(token, claims -> claims.get("roleName", String.class));
    }
    
    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }
    
    public Long extractRoleId(String token) {
        return extractClaim(token, claims -> claims.get("roleId", Long.class));
    }
    
    public String extractAuthSource(String token) {
        return extractClaim(token, claims -> claims.get("authSource", String.class));
    }
    
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    private Claims extractAllClaims(String token) {
        Key key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
    public Boolean validateToken(String token, User user) {
        final String username = extractUsername(token);
        final Long userId = extractUserId(token);
        return (username.equals(user.getEmail()) && 
                userId.equals(user.getUserId()) && 
                !isTokenExpired(token) &&
                !isTokenBlacklisted(token));
    }
    
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
    
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
    
    public String getTokenType(String token) {
        return extractClaim(token, claims -> claims.get("tokenType", String.class));
    }
}