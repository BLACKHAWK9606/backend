package com.bancassurance.authentication.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SmsResponse {
    
    @JsonProperty("status_code")
    private String statusCode;
    
    @JsonProperty("status_desc")
    private String statusDesc;
    
    @JsonProperty("message_id")
    private Long messageId;
    
    @JsonProperty("mobile_number")
    private String mobileNumber;
    
    @JsonProperty("network_id")
    private String networkId;
    
    @JsonProperty("message_cost")
    private Integer messageCost;
    
    @JsonProperty("credit_balance")
    private Integer creditBalance;
    
    public boolean isSuccess() {
        return "1000".equals(statusCode);
    }
}