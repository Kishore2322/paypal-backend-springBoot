package com.paypal.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

//@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    private String token;

    public String getToken() {
        return token;
    }

    public JwtResponse(String token) {
        this.token = token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
