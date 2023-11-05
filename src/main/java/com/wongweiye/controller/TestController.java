package com.wongweiye.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

    // spring security provide two ways to do access control
    // based on filter - http request before reach method to do verify - FilterSecurityInterceptor
    // based on AOP - MethodSecurityInterceptor
    // here is based on AOP
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN') or hasAuthority('SCOPE_ROLE_USER')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR') or hasAuthority('SCOPE_ROLE_MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_ROLE_ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
