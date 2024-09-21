package org.example.springsecurity.model.repository;

import org.example.springsecurity.model.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TokenRepository extends JpaRepository<Token, Long> {
    List<Token> findByToken(String token);
}
