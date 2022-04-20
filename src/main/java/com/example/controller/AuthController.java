package com.example.controller;

import com.example.entity.ConfirmationToken;
import com.example.entity.InvalidAccessToken;
import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.model.AuthProvider;
import com.example.repository.InvalidAccessTokenRepository;
import com.example.rest.*;
import com.example.service.ConfirmationTokenService;
import com.example.service.EmailSenderService;
import com.example.service.RefreshTokenService;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.UserService;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static javax.servlet.http.HttpServletResponse.*;
import static org.springframework.http.ResponseEntity.badRequest;
import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSenderService emailSenderService;
    private final InvalidAccessTokenRepository invalidAccessTokenRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider,
                          RefreshTokenService refreshTokenService, UserService userService,
                          ConfirmationTokenService confirmationTokenService, BCryptPasswordEncoder bCryptPasswordEncoder,
                          EmailSenderService emailSenderService, InvalidAccessTokenRepository invalidAccessTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
        this.confirmationTokenService = confirmationTokenService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.emailSenderService = emailSenderService;
        this.invalidAccessTokenRepository = invalidAccessTokenRepository;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> addUser(@RequestBody SignUp data) {
        if (userService.findUserByUsername(data.getUsername()).isPresent()){
            return badRequest().body("The user with this name is already exist!");
        }

        if (userService.findUserByEmail(data.getEmail()).isPresent()){
            return badRequest().body("The user with this email is already exist!");
        }

        User user = new User(data.getUsername(), data.getEmail(), data.getPassword());
        user.setProvider(AuthProvider.local);
        userService.saveUser(user);
        ConfirmationToken confirmationToken = confirmationTokenService.createConfirmationToken(user);

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(data.getEmail());
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("danpr080704@gmail.com");
        mailMessage.setText("To confirm your account, please click here : "
                +"http://localhost:8080/auth/confirm-signup?token="+confirmationToken.getToken());

        emailSenderService.sendEmail(mailMessage);

        return ok().build();
    }

    @GetMapping("/confirm-signup")
    public void confirmRegistration(HttpServletResponse response, @RequestParam("token") String token) throws IOException {
        Optional<ConfirmationToken> confirmationToken = confirmationTokenService.findByToken(token);

        if (confirmationToken.isEmpty() || confirmationTokenService.ifExpired(confirmationToken.get())) {
            response.sendError(SC_BAD_REQUEST);
            return;
        }

        User user = confirmationToken.get().getUser();
        user.setEnabled(true);
        userService.updateUser(user);
        confirmationTokenService.deleteByToken(confirmationToken.get().getToken());

        response.sendRedirect("http://localhost:3000/login");
    }

    @PostMapping("/login")
    public void signIn(@RequestBody AuthenticationRequest data, HttpServletResponse response) throws IOException {
        try {
            UserDetails user = userService.findUserByEmail(data.getEmail()).orElseThrow(() -> new UsernameNotFoundException(""));
            String username = user.getUsername();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, data.getPassword(), user.getAuthorities());
            authenticationManager.authenticate(authentication);

            String accessToken = jwtTokenProvider.generateJwtToken(user);

            Optional<RefreshToken> optionalRefreshToken = refreshTokenService.findByUsername(username);
            RefreshToken refreshToken;
            if (optionalRefreshToken.isEmpty() || !refreshTokenService.ifNonExpired(optionalRefreshToken.get())) {
                refreshTokenService.deleteToken(username);
                refreshToken = refreshTokenService.createToken(username);
            }
            else {
                refreshToken = optionalRefreshToken.get();
                refreshTokenService.updateToken(refreshToken);
            }

            Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setPath("/");

            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getToken());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setPath("/");

            response.addCookie(accessTokenCookie);
            response.addCookie(refreshTokenCookie);
            response.getWriter().print(username);
        } catch (UsernameNotFoundException e) {
            response.setStatus(401);
            response.getWriter().print(e.getMessage());
        }
    }

    @GetMapping("/get-cookies")
    public void googleLogin(@RequestParam("accessToken") String accessToken,
                            @RequestParam("refreshToken") String refreshToken,
                            HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    @PostMapping("/logout")
    public void logout(@CookieValue("accessToken") String accessToken) {
        System.out.println(accessToken);
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        refreshTokenService.deleteToken(username);

        InvalidAccessToken invalidAccessToken =
                new InvalidAccessToken(username, accessToken, jwtTokenProvider.getExpiration(accessToken));
        invalidAccessTokenRepository.save(invalidAccessToken);
    }

    @PostMapping("/renew-access-token")
    public void renewAccessToken(@CookieValue("refreshToken") String token, HttpServletResponse response) throws IOException {
        final Logger logger = LoggerFactory.getLogger(AuthController.class);

        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<RefreshToken> refreshToken = refreshTokenService.findByToken(token);
        if (refreshToken.isEmpty()) {
            logger.error("This refresh token doesn't exist");
            response.sendError(401);
            return;
        }

        UserDetails user = refreshToken.get().getUser();
        if (user.getUsername().equals(username) && refreshTokenService.ifNonExpired(refreshToken.get())) {
            refreshTokenService.updateToken(refreshToken.get());

            Cookie accessTokenCookie = new Cookie("accessToken", jwtTokenProvider.generateJwtToken(user));
            accessTokenCookie.setHttpOnly(true);
            response.addCookie(accessTokenCookie);
        }

        response.sendError(401);
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@CookieValue("accessToken") String accessToken,
                                                 @RequestBody ChangePasswordRequest data) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, data.getOldPassword()));

        User user = userService.findUserByUsername(username).orElseThrow();
        user.setPassword(bCryptPasswordEncoder.encode(data.getNewPassword()));
        userService.updateUser(user);

        InvalidAccessToken invalidAccessToken =
                new InvalidAccessToken(username, accessToken, jwtTokenProvider.getExpiration(accessToken));
        invalidAccessTokenRepository.save(invalidAccessToken);

        return ok().body(jwtTokenProvider.generateJwtToken(user));
    }

    @PostMapping("/change-username")
    public void changeUsername(@CookieValue("accessToken") String accessToken,
                               @RequestBody ChangeUsernameRequest data, HttpServletResponse response) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, data.getPassword()));

        User user = userService.findUserByUsername(username).orElseThrow();
        user.setUsername(data.getNewUsername());
        userService.updateUser(user);

        InvalidAccessToken invalidAccessToken =
                new InvalidAccessToken(username, accessToken, jwtTokenProvider.getExpiration(accessToken));
        invalidAccessTokenRepository.save(invalidAccessToken);

        Cookie accessTokenCookie = new Cookie("accessToken", jwtTokenProvider.generateJwtToken(user));
        accessTokenCookie.setHttpOnly(true);
        response.addCookie(accessTokenCookie);
    }

    @GetMapping("/reset-password")
    public void forgotPassword(String email, HttpServletResponse response) throws IOException {
        Optional<User> user = userService.findUserByEmail(email);
        if (user.isEmpty()) {
            response.sendError(401);
            return;
        }

        String newPassword = RandomStringUtils.random(15, true, true);
        String confirmationToken = confirmationTokenService.createConfirmationToken(user.get()).getToken();

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(email);
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("danpr080704@gmail.com");
        mailMessage.setText("Your new password will be : "+newPassword+"\nTo reset your password, please click here : "
                +"http://localhost:8080/auth/confirm-reset-password?token="+confirmationToken+"&password="+bCryptPasswordEncoder.encode(newPassword));

        emailSenderService.sendEmail(mailMessage);
    }

    @GetMapping("/confirm-reset-password")
    public void confirmResetPassword(HttpServletResponse response,
                                                  @RequestParam("token") String token, @RequestParam("password") String password) throws IOException {
        Optional<ConfirmationToken> confirmationToken = confirmationTokenService.findByToken(token);

        if (confirmationToken.isEmpty() || confirmationTokenService.ifExpired(confirmationToken.get())) {
            response.sendError(SC_BAD_REQUEST);
            return;
        }

        User user = confirmationToken.get().getUser();
        user.setPassword(password);
        userService.updateUser(user);
        confirmationTokenService.deleteByToken(confirmationToken.get().getToken());

        response.sendRedirect("http://localhost:3000/login");
    }

    @GetMapping("/if-authenticated")
    public void ifAuthenticated(HttpServletResponse response, @CookieValue("accessToken") String accessToken,
                                @CookieValue("refreshToken") String refreshToken) throws IOException {
        if (invalidAccessTokenRepository.findByToken(accessToken).isPresent() || refreshTokenService.findByToken(refreshToken).isEmpty()) {
            response.sendError(401);
        }
    }
}
