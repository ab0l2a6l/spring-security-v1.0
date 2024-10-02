package org.example.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springsecurity.model.entity.Token;
import org.example.springsecurity.model.repository.TokenRepository;
import org.example.springsecurity.model.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization"); // age login nakarde az inja begzare --- age login karde bayad token dashte bashe
        if (request.getRequestURI().equals("/rest/v1/login")) {
            filterChain.doFilter(request, response);
            return;
        } else if (authHeader == null) {
            response.getWriter().write("Unauthorized: Token is missing");
            return;
        }
        String jwt = authHeader.replace("Bearer ", "");
        System.out.println(jwt);
        String username = jwtService.getUsernameFromToken(jwt);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            Token finedToken = tokenRepository.findByToken(jwt)
                    .stream().filter(token -> !token.isExpired() &&
                            !token.isRevoked())
                    .collect(Collectors.toList())
                    .get(0);

            if (finedToken == null) {
                return;
            }
            UserDetails userDetails = userService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(
                    new WebAuthenticationDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
        filterChain.doFilter(request, response);
    }
}
