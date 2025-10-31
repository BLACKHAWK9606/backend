# Database Design Documentation - Bancassurance Authentication System

## Table of Contents
1. [Overview](#overview)
2. [Database Architecture](#database-architecture)
3. [RBAC Design Philosophy](#rbac-design-philosophy)
4. [Database Schema](#database-schema)
5. [Table Relationships](#table-relationships)
6. [Implementation Steps](#implementation-steps)
7. [Test Data Setup](#test-data-setup)
8. [Security Considerations](#security-considerations)
9. [Performance Optimization](#performance-optimization)
10. [Future Scalability](#future-scalability)

## Overview

### Purpose
This document provides comprehensive documentation for the database design of the bancassurance authentication system. The design implements a sophisticated Role-Based Access Control (RBAC) system that supports dynamic role management, granular permissions, and enterprise-level security requirements.

### Database System
- **Database Management System**: PostgreSQL 12+
- **Database Name**: `bancassurance_auth`
- **Character Encoding**: UTF-8
- **Collation**: English_United States.1252

### Design Principles
1. **Separation of Concerns**: Clear separation between users, roles, and permissions
2. **Scalability**: Dynamic role and permission management without code changes
3. **Security**: Comprehensive audit trails and access control
4. **Flexibility**: Support for multiple authentication sources
5. **Maintainability**: Normalized database structure with proper relationships

## Database Architecture

### High-Level Architecture
The authentication database follows a 4-table RBAC model:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    USERS    │    │    ROLES    │    │ PERMISSIONS │    │ACCESS_RIGHTS│
│             │    │             │    │             │    │             │
│ - user_id   │───▶│ - role_id   │◀──▶│-permission_id│◀──▶│-access_right│
│ - username  │    │ - role_name │    │-permission_ │    │- role_id    │
│ - email     │    │ - desc      │    │  name       │    │-permission_ │
│ - role_id   │    │ - is_active │    │- resource   │    │  id         │
│ - ...       │    │ - created_at│    │- action     │    │- granted_at │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### Relationship Types
- **Users ↔ Roles**: One-to-Many (One role can have multiple users, one user has one role)
- **Roles ↔ Permissions**: Many-to-Many (One role can have multiple permissions, one permission can belong to multiple roles)
- **Access Rights**: Junction table managing role-permission relationships

## RBAC Design Philosophy

### Core Concepts

#### 1. Dynamic Role Management
- **Superuser Control**: System superuser can create, modify, and delete roles
- **No Hard-coded Roles**: All roles except SUPERUSER are configurable
- **Role Hierarchy**: Support for organizational hierarchy through permission inheritance

#### 2. Granular Permission System
- **Resource-Action Model**: Permissions defined as resource:action pairs
- **Modular Permissions**: Each system function has dedicated permissions
- **Permission Categories**: Grouped by functional areas (policies, users, system)

#### 3. Centralized Access Control
- **Single Source of Truth**: All access rights managed through access_rights table
- **Inheritance Model**: Users inherit permissions through their assigned roles
- **Audit Trail**: Complete tracking of permission grants and modifications

### Business Logic Flow

#### User Authentication Flow
```
1. User Login Request
   ↓
2. Validate Credentials (Database/AD)
   ↓
3. Retrieve User Role
   ↓
4. Load Role Permissions from access_rights
   ↓
5. Generate JWT with User + Role + Permissions
   ↓
6. Return Authentication Token
```

#### Permission Check Flow
```
1. API Request with JWT
   ↓
2. Extract User Role from Token
   ↓
3. Check Required Permission for Endpoint
   ↓
4. Validate Role has Required Permission
   ↓
5. Allow/Deny Access
```

## Database Schema

### 1. Users Table
**Purpose**: Store user account information and authentication details

```sql
CREATE TABLE users (
    -- Primary Key
    user_id BIGSERIAL PRIMARY KEY,
    
    -- Identity Information
    username VARCHAR(100) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone_number VARCHAR(20),
    
    -- Authentication
    authentication_source VARCHAR(20) DEFAULT 'DATABASE' 
        CHECK (authentication_source IN ('DATABASE', 'ACTIVE_DIRECTORY')),
    password VARCHAR(255),
    password_reset_token VARCHAR(255),
    
    -- Account Status
    status VARCHAR(20) DEFAULT 'ACTIVE' 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'LOCKED')),
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Role Assignment
    role_id BIGINT NOT NULL,
    
    -- Audit Fields
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_logged_in BOOLEAN DEFAULT FALSE,
    is_first_login BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    
    -- Lifecycle Management
    is_deleted BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT FALSE,
    approval_timestamp TIMESTAMP,
    approved_by BIGINT,
    is_rejected BOOLEAN DEFAULT FALSE,
    rejection_timestamp TIMESTAMP,
    rejected_by BIGINT,
    rejection_reason TEXT,
    
    -- Security Policies
    remaining_days_till_password_reset INTEGER DEFAULT 90,
    has_accepted_terms BOOLEAN DEFAULT FALSE,
    
    -- Foreign Key Constraints
    CONSTRAINT fk_user_role FOREIGN KEY (role_id) REFERENCES roles(role_id),
    CONSTRAINT fk_approved_by FOREIGN KEY (approved_by) REFERENCES users(user_id),
    CONSTRAINT fk_rejected_by FOREIGN KEY (rejected_by) REFERENCES users(user_id)
);
```

#### Field Descriptions
- **user_id**: Auto-incrementing primary key
- **username**: Unique identifier for login
- **authentication_source**: Determines authentication method (local DB or Active Directory)
- **status**: Account status for administrative control
- **role_id**: Foreign key linking to user's assigned role
- **approval workflow**: Complete approval/rejection tracking
- **password_reset_token**: Temporary token for password reset functionality
- **has_accepted_terms**: Compliance tracking for terms and conditions

### 2. Roles Table
**Purpose**: Define system roles with metadata

```sql
CREATE TABLE roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);
```

#### Field Descriptions
- **role_id**: Auto-incrementing primary key
- **role_name**: Unique role identifier (e.g., 'SUPERUSER', 'POLICY_MANAGER')
- **role_description**: Human-readable role description
- **is_active**: Enable/disable roles without deletion
- **created_by**: Audit trail for role creation

### 3. Permissions Table
**Purpose**: Define granular system permissions

```sql
CREATE TABLE permissions (
    permission_id BIGSERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    permission_description TEXT,
    resource VARCHAR(50),
    action VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Field Descriptions
- **permission_id**: Auto-incrementing primary key
- **permission_name**: Unique permission identifier (e.g., 'create_policy')
- **resource**: System resource being accessed (e.g., 'policies', 'users')
- **action**: Action being performed (e.g., 'create', 'update', 'delete', 'view')
- **is_active**: Enable/disable permissions without deletion

### 4. Access Rights Table (Junction Table)
**Purpose**: Map roles to permissions (many-to-many relationship)

```sql
CREATE TABLE access_rights (
    access_right_id BIGSERIAL PRIMARY KEY,
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by BIGINT,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Foreign Key Constraints
    CONSTRAINT fk_access_rights_role FOREIGN KEY (role_id) 
        REFERENCES roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_rights_permission FOREIGN KEY (permission_id) 
        REFERENCES permissions(permission_id) ON DELETE CASCADE,
    
    -- Prevent Duplicate Mappings
    CONSTRAINT uk_role_permission UNIQUE (role_id, permission_id)
);
```

#### Field Descriptions
- **access_right_id**: Auto-incrementing primary key
- **role_id**: Foreign key to roles table
- **permission_id**: Foreign key to permissions table
- **granted_at**: Timestamp of permission grant
- **granted_by**: User who granted the permission (audit trail)
- **is_active**: Enable/disable specific role-permission mappings

## Table Relationships

### Entity Relationship Diagram
```
USERS (1) ────────── (M) ROLES (M) ────────── (M) PERMISSIONS
  │                           │                        │
  │                           │                        │
  │                           └──── ACCESS_RIGHTS ─────┘
  │                                      │
  │                                      │
  └─── approved_by/rejected_by ──────────┘
```

### Relationship Details

#### Users → Roles (Many-to-One)
- **Cardinality**: Many users can have the same role, but each user has exactly one role
- **Foreign Key**: users.role_id → roles.role_id
- **Business Rule**: Role assignment determines user's system permissions

#### Roles ↔ Permissions (Many-to-Many)
- **Cardinality**: One role can have multiple permissions, one permission can belong to multiple roles
- **Junction Table**: access_rights
- **Business Rule**: Permissions are assigned to roles, not directly to users

#### Self-Referencing Relationships
- **users.approved_by → users.user_id**: Tracks who approved the user
- **users.rejected_by → users.user_id**: Tracks who rejected the user

## Implementation Steps

### Step 1: Database Creation
```sql
-- Create the main database
CREATE DATABASE bancassurance_auth
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'English_United States.1252'
    LC_CTYPE = 'English_United States.1252'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;
```

### Step 2: Table Creation (Order Matters)
Execute in the following order due to foreign key dependencies:

#### 2.1 Create Roles Table
```sql
CREATE TABLE roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT
);
```

#### 2.2 Create Permissions Table
```sql
CREATE TABLE permissions (
    permission_id BIGSERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    permission_description TEXT,
    resource VARCHAR(50),
    action VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 2.3 Create Access Rights Table
```sql
CREATE TABLE access_rights (
    access_right_id BIGSERIAL PRIMARY KEY,
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by BIGINT,
    is_active BOOLEAN DEFAULT TRUE,
    
    CONSTRAINT fk_access_rights_role FOREIGN KEY (role_id) 
        REFERENCES roles(role_id) ON DELETE CASCADE,
    CONSTRAINT fk_access_rights_permission FOREIGN KEY (permission_id) 
        REFERENCES permissions(permission_id) ON DELETE CASCADE,
    CONSTRAINT uk_role_permission UNIQUE (role_id, permission_id)
);
```

#### 2.4 Create Users Table
```sql
CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone_number VARCHAR(20),
    authentication_source VARCHAR(20) DEFAULT 'DATABASE' 
        CHECK (authentication_source IN ('DATABASE', 'ACTIVE_DIRECTORY')),
    password VARCHAR(255),
    password_reset_token VARCHAR(255),
    status VARCHAR(20) DEFAULT 'ACTIVE' 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'LOCKED')),
    is_active BOOLEAN DEFAULT TRUE,
    role_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_logged_in BOOLEAN DEFAULT FALSE,
    is_first_login BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT FALSE,
    approval_timestamp TIMESTAMP,
    approved_by BIGINT,
    is_rejected BOOLEAN DEFAULT FALSE,
    rejection_timestamp TIMESTAMP,
    rejected_by BIGINT,
    rejection_reason TEXT,
    remaining_days_till_password_reset INTEGER DEFAULT 90,
    has_accepted_terms BOOLEAN DEFAULT FALSE,
    
    CONSTRAINT fk_user_role FOREIGN KEY (role_id) REFERENCES roles(role_id),
    CONSTRAINT fk_approved_by FOREIGN KEY (approved_by) REFERENCES users(user_id),
    CONSTRAINT fk_rejected_by FOREIGN KEY (rejected_by) REFERENCES users(user_id)
);
```

### Step 3: Index Creation for Performance
```sql
-- Users table indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX idx_users_status_active ON users(status, is_active);
CREATE INDEX idx_users_auth_source ON users(authentication_source);

-- Access rights indexes
CREATE INDEX idx_access_rights_role_id ON access_rights(role_id);
CREATE INDEX idx_access_rights_permission_id ON access_rights(permission_id);

-- Roles and permissions indexes
CREATE INDEX idx_roles_name ON roles(role_name);
CREATE INDEX idx_permissions_name ON permissions(permission_name);
CREATE INDEX idx_permissions_resource_action ON permissions(resource, action);
```

## Test Data Setup

### Initial System Setup

#### Step 1: Create Base Role
```sql
INSERT INTO roles (role_name, role_description, is_active, created_by) 
VALUES ('SUPERUSER', 'System administrator with full access to all system functions', TRUE, NULL);
```

#### Step 2: Create System Permissions
```sql
INSERT INTO permissions (permission_name, permission_description, resource, action, is_active) VALUES
-- Policy Management Permissions
('create_policy', 'Create new insurance policies', 'policies', 'create', TRUE),
('update_policy', 'Update existing insurance policies', 'policies', 'update', TRUE),
('delete_policy', 'Delete insurance policies', 'policies', 'delete', TRUE),
('view_policy', 'View insurance policies', 'policies', 'view', TRUE),

-- User Management Permissions
('create_user', 'Create new system users', 'users', 'create', TRUE),
('update_user', 'Update existing user information', 'users', 'update', TRUE),
('delete_user', 'Delete system users', 'users', 'delete', TRUE),
('view_user', 'View user information', 'users', 'view', TRUE),

-- Role & Permission Management
('create_role', 'Create new system roles', 'roles', 'create', TRUE),
('assign_permissions', 'Assign permissions to roles', 'permissions', 'assign', TRUE),
('view_role', 'View system roles and permissions', 'roles', 'view', TRUE),

-- System Administration
('system_configuration', 'Configure system settings', 'system', 'configure', TRUE);
```

#### Step 3: Grant All Permissions to SUPERUSER
```sql
INSERT INTO access_rights (role_id, permission_id, granted_by, is_active) VALUES
(1, 1, NULL, TRUE),   -- create_policy
(1, 2, NULL, TRUE),   -- update_policy
(1, 3, NULL, TRUE),   -- delete_policy
(1, 4, NULL, TRUE),   -- view_policy
(1, 5, NULL, TRUE),   -- create_user
(1, 6, NULL, TRUE),   -- update_user
(1, 7, NULL, TRUE),   -- delete_user
(1, 8, NULL, TRUE),   -- view_user
(1, 9, NULL, TRUE),   -- create_role
(1, 10, NULL, TRUE),  -- assign_permissions
(1, 11, NULL, TRUE),  -- view_role
(1, 12, NULL, TRUE);  -- system_configuration
```

#### Step 4: Create Initial Superuser
```sql
INSERT INTO users (
    username, first_name, last_name, email, phone_number, authentication_source, 
    password, status, is_active, role_id, is_approved, has_accepted_terms
) VALUES (
    'superuser', 'System', 'Administrator', 'superuser@bancassurance.com', '+1234567890',
    'DATABASE', '$2a$10$placeholder.hashed.password.here', 'ACTIVE', TRUE, 1, TRUE, TRUE
);
```

### Additional Test Roles and Users

#### Create Additional Roles
```sql
INSERT INTO roles (role_name, role_description, is_active, created_by) VALUES
('POLICY_MANAGER', 'Mid-level management role for policy operations and limited user oversight', TRUE, 1),
('POLICY_OFFICER', 'Front-line staff handling day-to-day policy operations', TRUE, 1),
('VIEWER', 'Read-only access for auditors, compliance, and reporting staff', TRUE, 1);
```

#### Assign Permissions to Roles

**POLICY_MANAGER Permissions:**
```sql
INSERT INTO access_rights (role_id, permission_id, granted_by, is_active) VALUES
(2, 1, 1, TRUE),   -- create_policy
(2, 2, 1, TRUE),   -- update_policy
(2, 4, 1, TRUE),   -- view_policy
(2, 8, 1, TRUE),   -- view_user
(2, 11, 1, TRUE),  -- view_role
(2, 12, 1, TRUE);  -- system_configuration
```

**POLICY_OFFICER Permissions:**
```sql
INSERT INTO access_rights (role_id, permission_id, granted_by, is_active) VALUES
(3, 1, 1, TRUE),   -- create_policy
(3, 2, 1, TRUE),   -- update_policy
(3, 4, 1, TRUE),   -- view_policy
(3, 8, 1, TRUE);   -- view_user
```

**VIEWER Permissions:**
```sql
INSERT INTO access_rights (role_id, permission_id, granted_by, is_active) VALUES
(4, 4, 1, TRUE),   -- view_policy
(4, 8, 1, TRUE),   -- view_user
(4, 11, 1, TRUE);  -- view_role
```

#### Create Test Users
```sql
INSERT INTO users (
    username, first_name, last_name, email, phone_number, authentication_source, 
    password, status, is_active, role_id, is_approved, has_accepted_terms
) VALUES
('john.manager', 'John', 'Smith', 'john.smith@bancassurance.com', '+1234567891', 'DATABASE', 
 '$2a$10$placeholder.hashed.password.here', 'ACTIVE', TRUE, 2, TRUE, TRUE),

('sarah.officer', 'Sarah', 'Johnson', 'sarah.johnson@bancassurance.com', '+1234567892', 'DATABASE', 
 '$2a$10$placeholder.hashed.password.here', 'ACTIVE', TRUE, 3, TRUE, TRUE),

('mike.viewer', 'Mike', 'Davis', 'mike.davis@bancassurance.com', '+1234567893', 'DATABASE', 
 '$2a$10$placeholder.hashed.password.here', 'ACTIVE', TRUE, 4, TRUE, TRUE);
```

### Test Data Summary

#### User-Role-Permission Matrix
| User | Role | Permissions Count | Key Permissions |
|------|------|-------------------|-----------------|
| superuser | SUPERUSER | 12 | All system permissions |
| john.manager | POLICY_MANAGER | 6 | Policy management + limited admin |
| sarah.officer | POLICY_OFFICER | 4 | Policy operations + user viewing |
| mike.viewer | VIEWER | 3 | Read-only access |

#### Permission Distribution
```
SUPERUSER (12 permissions):
├── Policy: create, update, delete, view
├── User: create, update, delete, view
├── Role: create, view
├── Permission: assign
└── System: configuration

POLICY_MANAGER (6 permissions):
├── Policy: create, update, view
├── User: view
├── Role: view
└── System: configuration

POLICY_OFFICER (4 permissions):
├── Policy: create, update, view
└── User: view

VIEWER (3 permissions):
├── Policy: view
├── User: view
└── Role: view
```

## Security Considerations

### Data Protection
1. **Password Hashing**: All passwords stored using BCrypt with salt
2. **Token Security**: JWT tokens with expiration and secure signing
3. **SQL Injection Prevention**: Parameterized queries and JPA repositories
4. **Input Validation**: Server-side validation for all user inputs

### Access Control
1. **Principle of Least Privilege**: Users get minimum required permissions
2. **Role-Based Security**: No direct user-permission assignments
3. **Audit Trails**: Complete logging of permission grants and access attempts
4. **Session Management**: Proper session handling and logout functionality

### Database Security
1. **Foreign Key Constraints**: Maintain referential integrity
2. **Check Constraints**: Validate data at database level
3. **Unique Constraints**: Prevent duplicate critical data
4. **Index Security**: Optimized queries without exposing sensitive data

## Performance Optimization

### Indexing Strategy
1. **Primary Keys**: Automatic B-tree indexes on all primary keys
2. **Foreign Keys**: Indexes on all foreign key columns
3. **Search Columns**: Indexes on frequently searched columns (email, username)
4. **Composite Indexes**: Multi-column indexes for complex queries

### Query Optimization
1. **Join Optimization**: Proper join strategies for role-permission queries
2. **Caching Strategy**: Cache frequently accessed role-permission mappings
3. **Connection Pooling**: Efficient database connection management
4. **Lazy Loading**: Load permissions only when needed

### Scalability Considerations
1. **Horizontal Scaling**: Database design supports read replicas
2. **Partitioning**: Future partitioning strategies for large user bases
3. **Archiving**: Soft delete strategy for maintaining audit trails
4. **Backup Strategy**: Regular backups with point-in-time recovery

## Future Scalability

### Planned Enhancements
1. **Hierarchical Roles**: Parent-child role relationships
2. **Time-Based Permissions**: Temporary permission grants
3. **Resource-Level Permissions**: Fine-grained resource access control
4. **Multi-Tenant Support**: Organization-based data isolation

### Migration Considerations
1. **Schema Versioning**: Database migration scripts for updates
2. **Backward Compatibility**: Maintain compatibility during upgrades
3. **Data Migration**: Scripts for moving between environments
4. **Performance Monitoring**: Continuous monitoring of database performance

## Conclusion

This database design provides a robust, scalable foundation for the bancassurance authentication system. The RBAC implementation offers:

- **Flexibility**: Dynamic role and permission management
- **Security**: Comprehensive access control and audit trails
- **Scalability**: Design supports growth and future enhancements
- **Maintainability**: Clear separation of concerns and proper normalization
- **Performance**: Optimized indexes and query patterns

The design successfully balances security requirements with operational flexibility, providing a solid foundation for enterprise-level authentication and authorization needs.