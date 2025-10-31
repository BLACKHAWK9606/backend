package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.AccessRight;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface AccessRightRepository extends JpaRepository<AccessRight, Long> {
    
    // Core permission queries for authentication
    @Query("SELECT ar.permission FROM AccessRight ar WHERE ar.role = :role AND ar.isActive = true")
    List<Permission> findActivePermissionsByRole(@Param("role") Role role);
    
    @Query("SELECT ar.permission.permissionName FROM AccessRight ar WHERE ar.role = :role AND ar.isActive = true")
    List<String> findActivePermissionNamesByRole(@Param("role") Role role);
    
    // Role-Permission relationship queries
    List<AccessRight> findByRole(Role role);
    List<AccessRight> findByPermission(Permission permission);
    List<AccessRight> findByRoleAndIsActiveTrue(Role role);
    
    // Existence checks
    boolean existsByRoleAndPermission(Role role, Permission permission);
    Optional<AccessRight> findByRoleAndPermission(Role role, Permission permission);
    
    // Permission management queries
    @Query("SELECT ar FROM AccessRight ar WHERE ar.role = :role AND ar.isActive = true ORDER BY ar.permission.resource, ar.permission.action")
    List<AccessRight> findActiveAccessRightsByRoleOrdered(@Param("role") Role role);
    
    @Query("SELECT ar FROM AccessRight ar WHERE ar.permission = :permission AND ar.isActive = true")
    List<AccessRight> findActiveAccessRightsByPermission(@Param("permission") Permission permission);
    
    // Admin queries
    @Query("SELECT COUNT(ar) FROM AccessRight ar WHERE ar.role = :role AND ar.isActive = true")
    long countActivePermissionsByRole(@Param("role") Role role);
    
    @Query("SELECT ar FROM AccessRight ar WHERE ar.grantedBy = :grantedBy ORDER BY ar.grantedAt DESC")
    List<AccessRight> findByGrantedBy(@Param("grantedBy") Long grantedBy);
    
    @Query("SELECT ar FROM AccessRight ar JOIN FETCH ar.role JOIN FETCH ar.permission ORDER BY ar.role.roleName, ar.permission.permissionName")
    List<AccessRight> findAllWithRoleAndPermission();
}