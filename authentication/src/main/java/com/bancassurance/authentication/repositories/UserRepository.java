package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.AuthenticationSource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // Authentication lookups
    Optional<User> findByEmail(String email);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByUsername(String username);
    
    // Existence checks
    boolean existsByEmail(String email);
    boolean existsByPhoneNumber(String phoneNumber);
    boolean existsByUsername(String username);
    
    // Multi-identifier lookup for unified login
    @Query("SELECT u FROM User u WHERE (u.email = :identifier OR u.phoneNumber = :identifier OR u.username = :identifier) AND u.isActive = true AND u.isDeleted = false")
    Optional<User> findByIdentifier(@Param("identifier") String identifier);
    
    // Role-based queries
    List<User> findByRole(Role role);
    List<User> findByRoleAndIsActiveTrue(Role role);
    
    // Status-based queries
    List<User> findByIsActiveTrueAndIsDeletedFalse();
    List<User> findByIsApprovedFalseAndIsDeletedFalse();
    List<User> findByIsRejectedFalseAndIsDeletedFalse();
    
    // Authentication source queries
    List<User> findByAuthenticationSource(AuthenticationSource authSource);
    
    // Admin queries
    @Query("SELECT u FROM User u WHERE u.isDeleted = false ORDER BY u.createdAt DESC")
    List<User> findAllActiveUsers();
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.isActive = true AND u.isDeleted = false")
    long countActiveUsers();
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.email = :email")
    Optional<User> findByEmailWithRole(@Param("email") String email);
    
    @Modifying
    @Query("UPDATE User u SET u.passwordResetToken = :token WHERE u.userId = :userId")
    void updatePasswordResetTokenById(@Param("userId") Long userId, @Param("token") String token);
    
    @Modifying
    @Query("UPDATE User u SET u.password = :password, u.passwordResetToken = null WHERE u.userId = :userId")
    void updatePasswordAndClearToken(@Param("userId") Long userId, @Param("password") String password);
    
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin, u.isLoggedIn = true WHERE u.userId = :userId")
    void updateLastLogin(@Param("userId") Long userId, @Param("lastLogin") LocalDateTime lastLogin);
    
    @Modifying
    @Query("UPDATE User u SET u.firstName = :firstName WHERE u.userId = :userId")
    void updateFirstName(@Param("userId") Long userId, @Param("firstName") String firstName);
}