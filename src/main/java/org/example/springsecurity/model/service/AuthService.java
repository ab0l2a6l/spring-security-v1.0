package org.example.springsecurity.model.service;

import org.example.springsecurity.config.ContextHelper;
import org.example.springsecurity.model.entity.User;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    public boolean checkLoadUser(User user) {
        return ContextHelper.getCurrentUser().getId().equals(user.getId());
    }
}
