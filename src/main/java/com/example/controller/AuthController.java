package com.example.controller;

import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.rest.AuthenticationRequest;
import com.example.rest.RefreshTokenRequest;
import com.example.service.RefreshTokenService;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.InvalidNameException;
import java.util.*;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider,
                          RefreshTokenService refreshTokenService, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
    }

    @PostMapping("/signin")
    public ResponseEntity<Object> signin(@RequestBody AuthenticationRequest data) {
        try {
            String username = data.getUsername();

            User user = userService.findUserByUsername(username);
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                    username, data.getPassword(), user.getAuthorities()));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtTokenProvider.generateJwtToken(authentication);
            String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

            HashMap<Object, Object> model = new HashMap<>();
            model.put("username", username);
            model.put("accessToken", accessToken);
            model.put("refreshToken", refreshToken);

            return ok(model);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied");
        }
    }

    @PostMapping("/renew-access-token")
    public ResponseEntity<Object> renewAccessToken(@RequestBody RefreshTokenRequest data) {
        final Logger logger = LoggerFactory.getLogger(AuthController.class);
        Map<Object, Object> model = new HashMap<>();
        HttpHeaders headers = new HttpHeaders();

        String username = data.getUsername();
        RefreshToken refreshToken;
        try {
            refreshToken = refreshTokenService.findByToken(data.getRefreshToken());
        } catch (InvalidNameException e) {
            logger.error("This refresh token doesn't exist");
            headers.add("TokenStatus", "invalid");
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        }

        UserDetails user = refreshToken.getUser();

        if (user.getUsername().equals(username) && refreshTokenService.verifyRefreshToken(refreshToken)) {
            String token = jwtTokenProvider.generateJwtToken(
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
            model.put("accessToken", token);
            return ok(model);
        }

        headers.add("TokenStatus", "expired");
        return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/renew-refresh-token")
    public ResponseEntity<?> renewRefreshToken(@RequestBody RefreshTokenRequest data) {
        final Logger logger = LoggerFactory.getLogger(AuthController.class);
        Map<Object, Object> model = new HashMap<>();

        String username = data.getUsername();
        RefreshToken refreshToken;
        try {
            refreshToken = refreshTokenService.findByToken(data.getRefreshToken());
        } catch (InvalidNameException e) {
            logger.error("This refresh token doesn't exist");
            HttpHeaders headers = new HttpHeaders();
            headers.add("TokenStatus", "invalid");
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        }

        User user  = refreshToken.getUser();

        if (user.getUsername().equals(username) && refreshTokenService.ifExpired(refreshToken)) {
            refreshTokenService.deleteByToken(refreshToken);
            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

            model.put("refreshToken", newRefreshToken.getToken());
            return ok(model);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.add("TokenStatus", "invalid");
        return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
    }
}
