package com.bancassurance.authentication.services;

import com.bancassurance.authentication.models.SmsRequest;
import com.bancassurance.authentication.models.SmsResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

@Service
public class EmTechSmsService {
    
    private static final Logger logger = LoggerFactory.getLogger(EmTechSmsService.class);
    private final WebClient webClient;
    
    @Value("${emtech.sms.api-url}")
    private String apiUrl;
    
    @Value("${emtech.sms.api-key}")
    private String apiKey;
    
    @Value("${emtech.sms.sender-id}")
    private String senderId;
    
    @Value("${emtech.sms.service-id}")
    private Integer serviceId;
    
    @jakarta.annotation.PostConstruct
    public void logConfiguration() {
        logger.info("=== EmTech SMS Configuration ===");
        logger.info("API URL: {}", apiUrl);
        logger.info("API Key: {}***", apiKey != null ? apiKey.substring(0, Math.min(10, apiKey.length())) : "null");
        logger.info("Sender ID: {}", senderId);
        logger.info("Service ID: {}", serviceId);
    }
    
    public EmTechSmsService(WebClient.Builder webClientBuilder) {
        logger.info("=== INITIALIZING EmTechSmsService ===");
        this.webClient = webClientBuilder
            .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024))
            .build();
        logger.info("WebClient initialized successfully");
    }
    
    public SmsResponse sendSms(String phoneNumber, String message) {
        logger.info("=== SMS SEND REQUEST START ===");
        logger.info("Phone: {}", phoneNumber);
        logger.info("Message: {}", message);
        logger.info("API URL: {}", apiUrl);
        logger.info("API Key: {}***", apiKey != null ? apiKey.substring(0, Math.min(10, apiKey.length())) : "null");
        logger.info("Sender ID: {}", senderId);
        logger.info("Service ID: {}", serviceId);
        
        try {
            SmsRequest request = new SmsRequest(
                apiKey,
                serviceId,
                phoneNumber,
                "json",
                senderId,
                message
            );
            
            logger.info("SMS Request created: {}", request);
            logger.info("Making HTTP POST to: {}", apiUrl);
            
            SmsResponse[] responses = webClient.post()
                .uri(apiUrl)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(SmsResponse[].class)
                .timeout(Duration.ofSeconds(30))
                .doOnSuccess(resp -> logger.info("SMS API Response received: {}", (Object) resp))
                .doOnError(error -> logger.error("SMS API Error: {}", error.getMessage(), (Object) error))
                .block();
            
            logger.info("SMS Response: {}", (Object) responses);
            
            if (responses != null && responses.length > 0) {
                logger.info("SMS sent successfully: {}", (Object) responses[0]);
                return responses[0];
            } else {
                logger.error("No response from SMS service");
                throw new RuntimeException("No response from SMS service");
            }
            
        } catch (Exception e) {
            logger.error("=== SMS SEND FAILED ===");
            logger.error("Error Type: {}", e.getClass().getSimpleName());
            logger.error("Error Message: {}", e.getMessage());
            logger.error("Full Stack Trace:", e);
            throw new RuntimeException("Failed to send SMS: " + e.getMessage(), e);
        }
    }
    
    public void sendOtpSms(String phoneNumber, String otpCode) {
        logger.info("=== OTP SMS REQUEST ===");
        logger.info("Sending OTP {} to phone {}", otpCode, phoneNumber);
        
        String message = String.format("Your BANCASSUR verification code is: %s. Valid for 5 minutes. Do not share this code.", otpCode);
        SmsResponse response = sendSms(phoneNumber, message);
        
        logger.info("OTP SMS Response: {}", (Object) response);
        
        if (!response.isSuccess()) {
            logger.error("SMS delivery failed: Status={}, Description={}", response.getStatusCode(), response.getStatusDesc());
            throw new RuntimeException("SMS delivery failed: " + response.getStatusDesc());
        }
        
        logger.info("OTP SMS sent successfully to {}", (Object) phoneNumber);
    }
}