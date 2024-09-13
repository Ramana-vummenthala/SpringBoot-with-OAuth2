package com.oauth2.custom_oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity(securedEnabled = true, // Enables @Secured
		prePostEnabled = true // Enables @PreAuthorize and @PostAuthorize
)
public class CustomOauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(CustomOauthApplication.class, args);
	}

}
