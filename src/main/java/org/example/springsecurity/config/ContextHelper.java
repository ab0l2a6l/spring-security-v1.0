package org.example.springsecurity.config;

import org.example.springsecurity.model.entity.User;
import org.springframework.security.core.context.SecurityContextHolder;

public class ContextHelper {
    public static User getCurrentUser() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
}
