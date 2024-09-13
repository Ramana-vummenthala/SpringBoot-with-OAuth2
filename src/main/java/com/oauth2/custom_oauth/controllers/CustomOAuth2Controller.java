package com.oauth2.custom_oauth.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import com.oauth2.custom_oauth.models.TokenResponse;
import com.oauth2.custom_oauth.services.JwtService;

@RestController
@RequestMapping("/oauth")
public class CustomOAuth2Controller {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public CustomOAuth2Controller(AuthenticationManager authenticationManager, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/token")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            String token = jwtService.generateToken(authentication);
            TokenResponse tokenResponse = new TokenResponse(token, "Bearer");
            return ResponseEntity.ok(tokenResponse);
        } catch (org.springframework.security.core.AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Credentials");
        }
    }
}
