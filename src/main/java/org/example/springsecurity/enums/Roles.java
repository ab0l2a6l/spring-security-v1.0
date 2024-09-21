package org.example.springsecurity.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Roles implements GrantedAuthority {
    ADMIN("ADMIN"),
    USER("USER");

    private String name;

    Roles(String name) {
        this.name = name;
    }

    @Override
    public String getAuthority() {
        return name;
    }
}
