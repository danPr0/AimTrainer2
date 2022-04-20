package com.example.service;

import com.example.entity.RefreshToken;
import com.example.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
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
    private final UserService userService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserService userService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public Optional<RefreshToken> findByUsername(String username) {
        return refreshTokenRepository.findByUserUsername(username);
    }

    public RefreshToken createToken(String username) {
        System.out.println(Instant.now().plusMillis(refreshTokenExpiration));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userService.findUserByUsername(username).orElseThrow());
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

    public void deleteToken(String username) {
        refreshTokenRepository.deleteByUserUsername(username);
    }
}
