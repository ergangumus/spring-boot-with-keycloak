package com.keycloak.keycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @GetMapping("/hi-user")
    @PreAuthorize("hasRole('client_user')")
    public String hiForUser() {
        return "hi user";
    }

    @GetMapping("/hi-admin")
    @PreAuthorize("hasRole('client_admin')")
    public String hiForAdmin() {
        return "hi admin";
    }

}
