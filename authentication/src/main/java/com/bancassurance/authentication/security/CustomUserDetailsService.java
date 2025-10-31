package com.bancassurance.authentication.security;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.UserRepository;
import com.bancassurance.authentication.services.PermissionService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionService permissionService;

    public CustomUserDetailsService(UserRepository userRepository, PermissionService permissionService) {
        this.userRepository = userRepository;
        this.permissionService = permissionService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmailWithRole(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        
        if (!user.getIsActive()) {
            throw new UsernameNotFoundException("User account is inactive");
        }
        
        if (user.getIsDeleted()) {
            throw new UsernameNotFoundException("User account has been deleted");
        }
        
        if (!user.getIsApproved()) {
            throw new UsernameNotFoundException("User account is pending approval");
        }
        
        // Load fresh permissions for maximum security
        List<String> permissions = permissionService.getUserPermissionNames(user);
        
        // Create authorities from permissions + role
        List<SimpleGrantedAuthority> authorities = permissions.stream()
                .map(permission -> new SimpleGrantedAuthority("PERM_" + permission))
                .collect(Collectors.toList());
        
        // Add role authority
        authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole().getRoleName()));
        
        return new org.springframework.security.core.userdetails.User(
            user.getEmail(),
            user.getPassword() != null ? user.getPassword() : "", // AD users have empty password
            authorities
        );
    }
}