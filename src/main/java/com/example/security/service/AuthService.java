package com.example.security.service;


import com.example.security.dto.SignInDto;
import com.example.security.dto.SignUpDto;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<?> authenticateUser(SignInDto loginRequest);
    ResponseEntity<?> registerUser(SignUpDto signUpRequest);
}
