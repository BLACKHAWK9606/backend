package com.bancassurance.authentication.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpMethodRequest {
    
    private String tempToken;
    private String method; // "SMS" or "EMAIL"
}