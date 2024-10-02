package org.example.springsecurity.model.service;

import lombok.RequiredArgsConstructor;
import org.example.springsecurity.config.JwtService;
import org.example.springsecurity.dto.UserRestLoginRequest;
import org.example.springsecurity.dto.UserRestLoginResponse;
import org.example.springsecurity.model.entity.Token;
import org.example.springsecurity.model.entity.User;
import org.example.springsecurity.model.repository.TokenRepository;
import org.example.springsecurity.model.repository.UserRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("user.not.found"));
    }

//    @PostAuthorize(value = "returnObject.username == authentication.name")
    @PostAuthorize(value = "@authService.checkLoadUser(returnObject)")
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("user.not.found"));
    }

    public void save(User user) {
        userRepository.save(user);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public UserRestLoginResponse login(UserRestLoginRequest userRestLoginRequest) {
        UserDetails userDetails = loadUserByUsername(userRestLoginRequest.getUsername());
        String token = jwtService.generateToken(userDetails);
        saveToken(token, userDetails);
        return new UserRestLoginResponse(token);
    }

    private void saveToken(String token, UserDetails userDetails) {
        Token buildToken = Token.builder()
                .token(token)
                .isExpired(false)
                .revoked(false)
                .user((User) userDetails)
                .build();
        tokenRepository.save(buildToken);
    }
}
