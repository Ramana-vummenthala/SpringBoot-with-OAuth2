package com.oauth2.custom_oauth.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

@Configuration
@Service
public class JwtService {

    @Value("${jwt-secret}")
    private String secretKey;

    public String generateToken(Authentication authentication) {
        UserDetails user = (UserDetails) authentication.getPrincipal();
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes()); // Convert secretKey to SecretKey

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("authorities", user.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(key)
                .compact();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(secretKeySpec).build();
    }

}

// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import io.jsonwebtoken.security.Keys;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Service;

// import java.security.Key;
// import java.util.Date;
// import java.util.stream.Collectors;
// import org.springframework.security.core.GrantedAuthority;

// @Service
// public class JwtService {

// // Generate a secret key for signing the JWT token
// private final Key key;

// public JwtService() {
// this.key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generates a secure
// secret key
// }

// public String generateToken(Authentication authentication) {
// UserDetails user = (UserDetails) authentication.getPrincipal();

// // Create the JWT token
// return Jwts.builder()
// .setSubject(user.getUsername())
// .claim("authorities", user.getAuthorities().stream()
// .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
// .setIssuedAt(new Date())
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1
// hour expiration
// .signWith(key) // Use the generated key to sign the token
// .compact();
// }
// }