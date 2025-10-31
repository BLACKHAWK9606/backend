package com.bancassurance.authentication.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "access_rights", 
       uniqueConstraints = @UniqueConstraint(columnNames = {"role_id", "permission_id"}))
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccessRight {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "access_right_id")
    private Long accessRightId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id", nullable = false)
    private Permission permission;
    
    @Column(name = "granted_at")
    private LocalDateTime grantedAt = LocalDateTime.now();
    
    @Column(name = "granted_by")
    private Long grantedBy;
    
    @Column(name = "is_active")
    private Boolean isActive = true;
    
    @PrePersist
    protected void onCreate() {
        if (grantedAt == null) {
            grantedAt = LocalDateTime.now();
        }
    }
}