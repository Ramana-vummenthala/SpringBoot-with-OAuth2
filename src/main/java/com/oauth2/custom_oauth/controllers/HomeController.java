package com.oauth2.custom_oauth.controllers;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class HomeController {

    @GetMapping("/home")
    public String getMethodName() {
        return "Hello World";
    }

    @Secured({ "ROLE_USER" })
    @GetMapping("/secured")
    public String getSecured() {
        return "Hello Secured World";
    }

}
