package com.bancassurance.authentication.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAnswerRequest {
    private Long questionId;
    private String answer;
}