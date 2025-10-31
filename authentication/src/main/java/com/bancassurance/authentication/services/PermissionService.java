package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.Permission;
import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.PermissionRepository;
import com.bancassurance.authentication.repositories.AccessRightRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final AccessRightRepository accessRightRepository;

    public PermissionService(PermissionRepository permissionRepository, 
                           AccessRightRepository accessRightRepository) {
        this.permissionRepository = permissionRepository;
        this.accessRightRepository = accessRightRepository;
    }
    
    /**
     * Get all active permissions for a user's role (for fresh loading)
     */
    public List<Permission> getUserPermissions(User user) {
        return accessRightRepository.findActivePermissionsByRole(user.getRole());
    }
    
    /**
     * Get permission names for a user's role (for JWT or quick checks)
     */
    public List<String> getUserPermissionNames(User user) {
        return accessRightRepository.findActivePermissionNamesByRole(user.getRole());
    }
    
    /**
     * Check if user has specific permission
     */
    public boolean hasPermission(User user, String permissionName) {
        List<String> userPermissions = getUserPermissionNames(user);
        return userPermissions.contains(permissionName);
    }
    
    /**
     * Check if user can perform action on resource
     */
    public boolean canPerformAction(User user, String resource, String action) {
        Optional<Permission> permission = permissionRepository.findByResourceAndAction(resource, action);
        if (permission.isEmpty()) {
            return false;
        }
        
        List<Permission> userPermissions = getUserPermissions(user);
        return userPermissions.contains(permission.get());
    }
    
    // Permission management methods
    public List<Permission> getAllActivePermissions() {
        return permissionRepository.findAllActivePermissionsOrdered();
    }
    
    public List<Permission> getPermissionsByResource(String resource) {
        return permissionRepository.findActivePermissionsByResource(resource);
    }
    
    public List<String> getAllResources() {
        return permissionRepository.findAllActiveResources();
    }
    
    public Optional<Permission> getPermissionByName(String permissionName) {
        return permissionRepository.findByPermissionName(permissionName);
    }
}