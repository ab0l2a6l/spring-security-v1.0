package org.example.springsecurity.controller;

import org.example.springsecurity.config.ContextHelper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/index")
public class IndexController {

    @GetMapping
    public String init() {
        return "index";
    }

    @GetMapping("/products")
    public String products() {
        return "products";
    }

    @GetMapping("/userdetails")
    public String getUserDetails(Model model) {
        model.addAttribute("user", ContextHelper.getCurrentUser());
        return "userDetails";
    }
}
