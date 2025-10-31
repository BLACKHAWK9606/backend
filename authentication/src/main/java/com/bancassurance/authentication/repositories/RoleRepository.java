package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    // Role lookup
    Optional<Role> findByRoleName(String roleName);
    boolean existsByRoleName(String roleName);
    
    // Active roles
    List<Role> findByIsActiveTrue();
    
    // Role management queries
    @Query("SELECT r FROM Role r WHERE r.isActive = true ORDER BY r.roleName")
    List<Role> findAllActiveRolesOrdered();
    
    @Query("SELECT COUNT(r) FROM Role r WHERE r.isActive = true")
    long countActiveRoles();
    
    // Find roles created by specific user
    List<Role> findByCreatedBy(Long createdBy);
}