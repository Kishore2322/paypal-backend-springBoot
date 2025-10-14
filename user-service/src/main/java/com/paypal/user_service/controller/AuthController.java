package com.paypal.user_service.controller;

import com.paypal.user_service.dto.JwtResponse;
import com.paypal.user_service.dto.LoginRequest;
import com.paypal.user_service.dto.SignupRequest;
import com.paypal.user_service.entity.User;
import com.paypal.user_service.repository.UserRepository;
import com.paypal.user_service.util.JwtUtil;
//import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
//@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());

        if (existingUser.isPresent()) { return ResponseEntity.badRequest().body("User already exists");}

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setRole("ROLE_USER");
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not found");
        }

        User user = userOptional.get();
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole());

        String token = jwtUtil.generateToken(claims, user.getEmail());
        return ResponseEntity.ok(new JwtResponse(token));
    }
}
