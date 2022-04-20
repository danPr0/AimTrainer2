package com.example.service;

import com.example.entity.ConfirmationToken;
import com.example.entity.User;
import com.example.repository.ConfirmationTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class ConfirmationTokenService {
    @Value("${security.jwt.confirmationToken.expire-length}")
    private int confirmationTokenExpiration;

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ConfirmationTokenService(ConfirmationTokenRepository confirmationTokenRepository) {
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    public Optional<ConfirmationToken> findByToken(String token){
        return confirmationTokenRepository.findByToken(token);
    }

    public ConfirmationToken createConfirmationToken(User user) {
        Optional<ConfirmationToken> existToken = confirmationTokenRepository.findByUser(user);
        if (existToken.isPresent()) {
            existToken.get().setExpiryDate(new Date(new Date().getTime() + confirmationTokenExpiration));
            existToken.get().setToken(UUID.randomUUID().toString());
            return existToken.get();
        }

        ConfirmationToken confirmationToken = new ConfirmationToken();
        confirmationToken.setUser(user);
        confirmationToken.setExpiryDate(new Date(new Date().getTime() + confirmationTokenExpiration));
        confirmationToken.setToken(UUID.randomUUID().toString());
        confirmationTokenRepository.save(confirmationToken);
        return confirmationToken;
    }

    public boolean ifExpired(ConfirmationToken token) {
        return token.getExpiryDate().compareTo(new Date()) < 0;
    }

    public void deleteByToken(String confirmationToken) {
        confirmationTokenRepository.deleteByToken(confirmationToken);
    }
}
