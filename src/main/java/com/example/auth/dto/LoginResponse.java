package com.example.auth.dto;

public record LoginResponse(String accessToken, String tokenType, Long expiresIn) {}