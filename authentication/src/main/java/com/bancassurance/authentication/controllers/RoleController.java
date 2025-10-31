package com.bancassurance.authentication.controllers;

import com.bancassurance.authentication.models.Role;
import com.bancassurance.authentication.models.Permission;
import com.bancassurance.authentication.models.AccessRight;
import com.bancassurance.authentication.models.User;
import com.bancassurance.authentication.repositories.RoleRepository;
import com.bancassurance.authentication.repositories.PermissionRepository;
import com.bancassurance.authentication.repositories.AccessRightRepository;
import com.bancassurance.authentication.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/roles")
@Tag(name = "Role Management", description = "Dynamic role management and permission assignment")
@SecurityRequirement(name = "Bearer Authentication")
public class RoleController {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final AccessRightRepository accessRightRepository;
    private final UserService userService;

    public RoleController(RoleRepository roleRepository, PermissionRepository permissionRepository,
                         AccessRightRepository accessRightRepository, UserService userService) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.accessRightRepository = accessRightRepository;
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('PERM_read_role')")
    @Operation(summary = "Get All Roles", description = "Retrieve all active roles (requires read_role permission)")
    @ApiResponse(responseCode = "200", description = "Roles retrieved successfully")
    @ApiResponse(responseCode = "403", description = "Access denied - read_role permission required")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleRepository.findAllActiveRolesOrdered());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('PERM_read_role')")
    @Operation(summary = "Get Role by ID", description = "Retrieve role details by ID (requires read_role permission)")
    @ApiResponse(responseCode = "200", description = "Role found")
    @ApiResponse(responseCode = "404", description = "Role not found")
    @ApiResponse(responseCode = "403", description = "Access denied - read_role permission required")
    public ResponseEntity<?> getRoleById(@PathVariable Long id) {
        Optional<Role> role = roleRepository.findById(id);
        return role.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('PERM_create_role')")
    @Operation(
        summary = "Create Role", 
        description = "Create a new system role (requires create_role permission)",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Role creation details",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Create Role Example",
                    value = "{\"roleName\": \"CLAIMS_OFFICER\", \"roleDescription\": \"Insurance claims processing officer with limited policy access\"}"
                )
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Role created successfully")
    @ApiResponse(responseCode = "400", description = "Invalid input or role already exists")
    @ApiResponse(responseCode = "403", description = "Access denied - create_role permission required")
    public ResponseEntity<?> createRole(@RequestBody Map<String, String> roleRequest) {
        try {
            String roleName = roleRequest.get("roleName");
            String roleDescription = roleRequest.get("roleDescription");
            
            if (roleName == null || roleName.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Role name is required"));
            }
            
            if (roleRepository.existsByRoleName(roleName)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Role name already exists"));
            }
            
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User currentUser = userService.getCurrentUser(authentication);
            
            Role role = new Role();
            role.setRoleName(roleName.toUpperCase());
            role.setRoleDescription(roleDescription);
            role.setIsActive(true);
            role.setCreatedAt(LocalDateTime.now());
            role.setCreatedBy(currentUser.getUserId());
            
            Role savedRole = roleRepository.save(role);
            return ResponseEntity.ok(savedRole);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('PERM_read_role')")
    @Operation(summary = "Get Role Permissions", description = "Get all permissions assigned to a role (requires read_role permission)")
    @ApiResponse(responseCode = "200", description = "Role permissions retrieved successfully")
    @ApiResponse(responseCode = "404", description = "Role not found")
    @ApiResponse(responseCode = "403", description = "Access denied - read_role permission required")
    public ResponseEntity<?> getRolePermissions(@PathVariable Long id) {
        Optional<Role> roleOptional = roleRepository.findById(id);
        if (roleOptional.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Role role = roleOptional.get();
        List<Permission> permissions = accessRightRepository.findActivePermissionsByRole(role);
        
        Map<String, Object> response = new HashMap<>();
        response.put("role", role);
        response.put("permissions", permissions);
        response.put("permissionCount", permissions.size());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('PERM_read_role')")
    @Operation(summary = "Get All Permissions", description = "Get all available system permissions (requires read_role permission)")
    @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully")
    @ApiResponse(responseCode = "403", description = "Access denied - read_role permission required")
    public ResponseEntity<List<Permission>> getAllPermissions() {
        return ResponseEntity.ok(permissionRepository.findAllActivePermissionsOrdered());
    }

    @PostMapping("/access-rights")
    @PreAuthorize("hasAuthority('PERM_assign_permissions')")
    @Operation(
        summary = "Assign Permission to Role", 
        description = "Assign a permission to a role (requires assign_permissions permission)",
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Permission assignment details",
            content = @Content(
                mediaType = "application/json",
                examples = @ExampleObject(
                    name = "Assign Permission Example",
                    value = "{\"roleId\": 2, \"permissionId\": 4}"
                )
            )
        )
    )
    @ApiResponse(responseCode = "200", description = "Permission assigned successfully")
    @ApiResponse(responseCode = "400", description = "Invalid input or permission already assigned")
    @ApiResponse(responseCode = "403", description = "Access denied - assign_permissions permission required")
    public ResponseEntity<?> assignPermissionToRole(@RequestBody Map<String, Object> assignmentRequest) {
        try {
            Long roleId = Long.valueOf(assignmentRequest.get("roleId").toString());
            Long permissionId = Long.valueOf(assignmentRequest.get("permissionId").toString());
            
            Optional<Role> roleOptional = roleRepository.findById(roleId);
            Optional<Permission> permissionOptional = permissionRepository.findById(permissionId);
            
            if (roleOptional.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid role ID"));
            }
            
            if (permissionOptional.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid permission ID"));
            }
            
            Role role = roleOptional.get();
            Permission permission = permissionOptional.get();
            
            // Check if already assigned
            if (accessRightRepository.existsByRoleAndPermission(role, permission)) {
                return ResponseEntity.badRequest().body(Map.of("error", "Permission already assigned to role"));
            }
            
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User currentUser = userService.getCurrentUser(authentication);
            
            AccessRight accessRight = new AccessRight();
            accessRight.setRole(role);
            accessRight.setPermission(permission);
            accessRight.setGrantedAt(LocalDateTime.now());
            accessRight.setGrantedBy(currentUser.getUserId());
            accessRight.setIsActive(true);
            
            AccessRight savedAccessRight = accessRightRepository.save(accessRight);
            return ResponseEntity.ok(savedAccessRight);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @DeleteMapping("/access-rights/{id}")
    @PreAuthorize("hasAuthority('PERM_assign_permissions')")
    @Operation(
        summary = "Revoke Permission from Role", 
        description = "Revoke a permission from a role (requires assign_permissions permission)"
    )
    @ApiResponse(responseCode = "200", description = "Permission revoked successfully")
    @ApiResponse(responseCode = "404", description = "Access right not found")
    @ApiResponse(responseCode = "403", description = "Access denied - assign_permissions permission required")
    public ResponseEntity<?> revokePermissionFromRole(@PathVariable Long id) {
        Optional<AccessRight> accessRightOptional = accessRightRepository.findById(id);
        if (accessRightOptional.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AccessRight accessRight = accessRightOptional.get();
        accessRight.setIsActive(false);
        accessRightRepository.save(accessRight);
        
        return ResponseEntity.ok(Map.of("message", "Permission revoked successfully"));
    }

    @GetMapping("/access-rights")
    @PreAuthorize("hasAuthority('PERM_read_role')")
    @Operation(summary = "Get All Access Rights", description = "Get all role-permission mappings (requires read_role permission)")
    @ApiResponse(responseCode = "200", description = "Access rights retrieved successfully")
    @ApiResponse(responseCode = "403", description = "Access denied - read_role permission required")
    public ResponseEntity<List<AccessRight>> getAllAccessRights() {
        return ResponseEntity.ok(accessRightRepository.findAllWithRoleAndPermission());
    }
}