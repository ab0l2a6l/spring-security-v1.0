package org.example.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.example.springsecurity.dto.UserSaveRequest;
import org.example.springsecurity.enums.Roles;
import org.example.springsecurity.model.entity.User;
import org.example.springsecurity.model.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Collections;
import java.util.Optional;

@Controller
public class LoginController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public LoginController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("userSaveRequest", new UserSaveRequest("1", "1"));
        return "register";
    }

    @PostMapping("/register")
    public String saveUser(@ModelAttribute @Valid UserSaveRequest userSaveRequest,
                           BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "register";
        }
        User user = new User();
        user.setUsername(userSaveRequest.username());
        user.setPassword(passwordEncoder.encode(userSaveRequest.password()));
        user.setEnable(true);
        user.setRoleList(Collections.singletonList(Roles.USER));
        userService.save(user);
        return "redirect:/login";
    }

}
