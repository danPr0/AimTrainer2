package com.example.repository;

import com.example.entity.InvalidAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface InvalidAccessTokenRepository extends JpaRepository<InvalidAccessToken, Long> {
    Optional<InvalidAccessToken> findByToken(String token);
}
