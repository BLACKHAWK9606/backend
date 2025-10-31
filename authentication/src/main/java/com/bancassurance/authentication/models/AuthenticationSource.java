package com.bancassurance.authentication.models;

public enum AuthenticationSource {
    EMAIL,              // Email + Password (local DB)
    PHONE,              // Phone + Password (local DB)
    ACTIVE_DIRECTORY    // AD Email + Password (LDAP)
}