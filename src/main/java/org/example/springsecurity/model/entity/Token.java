package org.example.springsecurity.model.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private boolean isExpired;
    private boolean revoked;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime creationAt;

    @ManyToOne
    private User user;
}
