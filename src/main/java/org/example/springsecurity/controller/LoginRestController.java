package org.example.springsecurity.controller;

import org.example.springsecurity.dto.UserRestLoginRequest;
import org.example.springsecurity.dto.UserRestLoginResponse;
import org.example.springsecurity.model.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/v1")
public class LoginRestController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;

    public LoginRestController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<UserRestLoginResponse> login(@RequestBody UserRestLoginRequest userRestLoginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                userRestLoginRequest.getUsername(),
                userRestLoginRequest.getPassword()
                )
        );
        UserRestLoginResponse login = userService.login(userRestLoginRequest);
        return ResponseEntity.ok(login);
    }
}
