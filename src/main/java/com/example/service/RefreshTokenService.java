package com.example.service;

import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class RefreshTokenService {
    @Value("${security.jwt.refreshToken.expire-length}")
    private int refreshTokenExpiration;

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createToken(User user) {
        System.out.println(Instant.now().plusMillis(refreshTokenExpiration));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(new Date(new Date().getTime() + refreshTokenExpiration));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public boolean ifNonExpired(RefreshToken token) {
        return token.getExpiryDate().compareTo(new Date()) >= 0;
    }

    public void updateToken(RefreshToken refreshToken) {
        refreshToken.setExpiryDate(new Date(new Date().getTime() + refreshTokenExpiration));
        refreshTokenRepository.save(refreshToken);
    }

    public void deleteToken(User user) {
        refreshTokenRepository.deleteByUser(user);
    }

    public void deleteToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }
}
