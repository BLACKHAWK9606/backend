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
    Optional<User> findByPasswordResetToken(String passwordResetToken);
    
    // Existence checks
    boolean existsByEmail(String email);
    boolean existsByPhoneNumber(String phoneNumber);
    boolean existsByUsername(String username);
    boolean existsByPasswordResetToken(String passwordResetToken);
    
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
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.isDeleted = false ORDER BY u.createdAt DESC")
    List<User> findAllActiveUsersWithRole();
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.isActive = true AND u.isDeleted = false")
    long countActiveUsers();
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.email = :email")
    Optional<User> findByEmailWithRole(@Param("email") String email);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.userId = :userId")
    Optional<User> findByIdWithRole(@Param("userId") Long userId);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.username = :username")
    Optional<User> findByUsernameWithRole(@Param("username") String username);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.phoneNumber = :phoneNumber")
    Optional<User> findByPhoneNumberWithRole(@Param("phoneNumber") String phoneNumber);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE (u.email = :identifier OR u.phoneNumber = :identifier OR u.username = :identifier) AND u.isActive = true AND u.isDeleted = false")
    Optional<User> findByIdentifierWithRole(@Param("identifier") String identifier);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.isApproved = false AND u.isDeleted = false")
    List<User> findPendingApprovalUsersWithRole();
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.role = :role")
    List<User> findByRoleWithRole(@Param("role") Role role);
    
    @Query("SELECT u FROM User u JOIN FETCH u.role WHERE u.role = :role AND u.isActive = true")
    List<User> findByRoleAndIsActiveTrueWithRole(@Param("role") Role role);
    
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