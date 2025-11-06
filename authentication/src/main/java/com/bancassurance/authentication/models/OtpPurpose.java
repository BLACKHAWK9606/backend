package com.bancassurance.authentication.models;

public enum OtpPurpose {
    LOGIN,              // For 2FA login verification
    PHONE_VERIFICATION, // For registration phone verification
    PASSWORD_RESET      // For password reset verification
}