package com.bancassurance.authentication.security;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.UserRepository;
import com.bancassurance.authentication.services.JwtService;
import com.bancassurance.authentication.services.PermissionService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final PermissionService permissionService;

    public JwtFilter(JwtService jwtService, UserDetailsService userDetailsService, 
                     UserRepository userRepository, PermissionService permissionService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.permissionService = permissionService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        jwt = authHeader.substring(7);
        
        try {
            userEmail = jwtService.extractUsername(jwt);
            
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                
                // Get the User entity from repository with role eagerly loaded
                Optional<User> userOptional = userRepository.findByEmailWithRole(userEmail);
                
                if (userOptional.isPresent() && jwtService.validateToken(jwt, userOptional.get())) {
                    User user = userOptional.get();
                    
                    // Fresh permission loading for maximum security
                    List<String> permissions = permissionService.getUserPermissionNames(user);
                    
                    // Create authorities from fresh permissions + role
                    List<SimpleGrantedAuthority> authorities = permissions.stream()
                            .map(permission -> new SimpleGrantedAuthority("PERM_" + permission))
                            .collect(Collectors.toList());
                    
                    // Add role authority
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole().getRoleName()));
                    
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        authorities
                    );
                    
                    // Add user info to authentication details for easy access
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            logger.error("JWT Authentication Error", e);
            // Clear security context on any error
            SecurityContextHolder.clearContext();
        }
        
        filterChain.doFilter(request, response);
    }
}