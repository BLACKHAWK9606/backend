package com.bancassurance.authentication.config;

import com.bancassurance.authentication.security.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(request -> {
                var corsConfig = new org.springframework.web.cors.CorsConfiguration();
                corsConfig.setAllowedOriginPatterns(java.util.List.of("*"));
                corsConfig.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                corsConfig.setAllowedHeaders(java.util.List.of("*"));
                corsConfig.setAllowCredentials(true);
                return corsConfig;
            }))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/error").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/swagger-ui.html").permitAll()
                .requestMatchers("/v3/api-docs/**").permitAll()
                
                // CORS preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // User profile endpoints (authenticated users)
                .requestMatchers(HttpMethod.GET, "/api/users/profile").authenticated()
                .requestMatchers(HttpMethod.PUT, "/api/users/profile").authenticated()
                .requestMatchers(HttpMethod.PUT, "/api/users/change-password").authenticated()
                
                // User Management - CRUD permissions
                .requestMatchers(HttpMethod.GET, "/api/users").hasAuthority("PERM_read_user")
                .requestMatchers(HttpMethod.POST, "/api/users").hasAuthority("PERM_create_user")
                .requestMatchers(HttpMethod.PUT, "/api/users/{id}").hasAuthority("PERM_update_user")
                .requestMatchers(HttpMethod.DELETE, "/api/users/{id}").hasAuthority("PERM_delete_user")
                .requestMatchers(HttpMethod.GET, "/api/users/pending").hasAuthority("PERM_read_user")
                
                // Role Management - CRUD permissions
                .requestMatchers(HttpMethod.GET, "/api/roles").hasAuthority("PERM_read_role")
                .requestMatchers(HttpMethod.POST, "/api/roles").hasAuthority("PERM_create_role")
                
                // Permission Management - CRUD permissions
                .requestMatchers(HttpMethod.POST, "/api/access-rights").hasAuthority("PERM_assign_permissions")
                .requestMatchers(HttpMethod.GET, "/api/permissions").hasAuthority("PERM_read_role")
                .requestMatchers(HttpMethod.GET, "/api/access-rights").hasAuthority("PERM_read_role")
                
                // Policy Management - CRUD permissions
                .requestMatchers(HttpMethod.GET, "/api/policies").hasAuthority("PERM_read_policy")
                .requestMatchers(HttpMethod.POST, "/api/policies").hasAuthority("PERM_create_policy")
                .requestMatchers(HttpMethod.PUT, "/api/policies/{id}").hasAuthority("PERM_update_policy")
                .requestMatchers(HttpMethod.DELETE, "/api/policies/{id}").hasAuthority("PERM_delete_policy")
                
                // System Configuration - Using actual database permissions
                .requestMatchers("/api/system/**").hasAuthority("PERM_system_configuration")
                
                // Default: require authentication
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}