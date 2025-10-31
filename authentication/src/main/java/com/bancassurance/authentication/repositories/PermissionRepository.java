package com.bancassurance.authentication.repositories;

import com.bancassurance.authentication.models.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    
    // Permission lookup
    Optional<Permission> findByPermissionName(String permissionName);
    boolean existsByPermissionName(String permissionName);
    
    // Resource-Action queries
    Optional<Permission> findByResourceAndAction(String resource, String action);
    List<Permission> findByResource(String resource);
    List<Permission> findByAction(String action);
    
    // Active permissions
    List<Permission> findByIsActiveTrue();
    
    // Permission management queries
    @Query("SELECT p FROM Permission p WHERE p.isActive = true ORDER BY p.resource, p.action")
    List<Permission> findAllActivePermissionsOrdered();
    
    @Query("SELECT p FROM Permission p WHERE p.resource = :resource AND p.isActive = true")
    List<Permission> findActivePermissionsByResource(@Param("resource") String resource);
    
    @Query("SELECT DISTINCT p.resource FROM Permission p WHERE p.isActive = true ORDER BY p.resource")
    List<String> findAllActiveResources();
    
    @Query("SELECT COUNT(p) FROM Permission p WHERE p.isActive = true")
    long countActivePermissions();
}