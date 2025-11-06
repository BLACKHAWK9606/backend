package com.bancassurance.authentication.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SmsRequest {
    
    @JsonProperty("api_key")
    private String apiKey;
    
    @JsonProperty("service_id")
    private Integer serviceId = 0;
    
    @JsonProperty("mobile")
    private String mobile;
    
    @JsonProperty("response_type")
    private String responseType = "json";
    
    @JsonProperty("shortcode")
    private String shortcode;
    
    @JsonProperty("message")
    private String message;
}