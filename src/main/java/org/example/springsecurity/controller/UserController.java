package org.example.springsecurity.controller;

import org.example.springsecurity.model.entity.User;
import org.example.springsecurity.model.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize(value = "hasAnyAuthority('ADMIN')")
    public ResponseEntity<?> getUsers() {
        return ResponseEntity.ok("this is all users");
    }

    @GetMapping("/id/{id}")
    public ResponseEntity<User> findById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.findById(id));
    }


    @GetMapping("/helloworld") // jwt login test
    public String helloWorld() {
        return "hello world";
    }
}
