package org.example.springsecurity.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import org.springframework.lang.NonNull;

public record UserSaveRequest(@NotEmpty @NonNull @Size(min = 1, max = 20) String username,
                              @NotEmpty @NonNull @Size(min = 1, max = 20) String password) {
}
