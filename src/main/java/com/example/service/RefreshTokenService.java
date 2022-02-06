package com.example.service;

import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.InvalidNameException;
import javax.transaction.Transactional;
import java.time.Instant;
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

    public RefreshToken findByToken(String token) throws InvalidNameException {
        return refreshTokenRepository.findByToken(token).orElseThrow(InvalidNameException::new);
    }

    public RefreshToken createRefreshToken(User user) {
        System.out.println(Instant.now().plusMillis(refreshTokenExpiration));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpiration));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public boolean verifyRefreshToken(RefreshToken token) {
        return token.getExpiryDate().compareTo(Instant.now()) >= 0;
    }

    public boolean ifExpired(RefreshToken token) {
        return token.getExpiryDate().compareTo(Instant.now()) < 0;
    }

    public void deleteByToken(RefreshToken token) {
        refreshTokenRepository.deleteByToken(token.getToken());
    }
}
