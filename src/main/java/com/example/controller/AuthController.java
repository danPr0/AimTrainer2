package com.example.controller;

import com.example.entity.ConfirmationToken;
import com.example.entity.InvalidAccessToken;
import com.example.entity.RefreshToken;
import com.example.entity.User;
import com.example.exception.UserAlreadyExistException;
import com.example.model.AuthProvider;
import com.example.repository.InvalidAccessTokenRepository;
import com.example.rest.AuthenticationRequest;
import com.example.rest.ChangePasswordRequest;
import com.example.rest.ChangeUsernameRequest;
import com.example.rest.SignUp;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.ConfirmationTokenService;
import com.example.service.EmailSenderService;
import com.example.service.RefreshTokenService;
import com.example.service.UserService;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.Size;
import java.io.IOException;
import java.util.NoSuchElementException;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
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

    @Value("${security.jwt.accessToken.expire-length}")
    private int accessTokenExpiration;

    @Value("${security.jwt.refreshToken.expire-length}")
    private int refreshTokenExpiration;

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

    public Cookie createCookie(String name, String value, Boolean httpOnly, String path, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(path);
        cookie.setMaxAge(maxAge/1000);
        return cookie;
    }

    public void createTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        response.addCookie(createCookie("accessToken", accessToken, true, "/", accessTokenExpiration));
        response.addCookie(createCookie("accessTokenClone", "", false, "/", accessTokenExpiration));
        response.addCookie(createCookie("refreshToken", refreshToken, true, "/", refreshTokenExpiration));
    }

    public void deleteTokenCookies(HttpServletResponse response) {
        response.addCookie(createCookie("accessToken", null, true, "/", 0));
        response.addCookie(createCookie("accessTokenClone", null, false, "/", 0));
        response.addCookie(createCookie("refreshToken", null, true, "/", 0));
    }

    public String getCurrentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @PostMapping("/signup")
    public ResponseEntity<?> addUser(@Valid @RequestBody SignUp data) {
        if (userService.findUserByUsername(data.getUsername()).isPresent())
            return badRequest().body("The user with this nickname is already exist!");

        if (userService.findUserByEmail(data.getEmail()).isPresent())
            return badRequest().body("The user with this email is already exist!");

        User user = new User(data.getUsername(), data.getEmail(), data.getPassword());
        user.setProvider(AuthProvider.local);
        userService.saveUser(user);
        ConfirmationToken confirmationToken = confirmationTokenService.createConfirmationToken(user);

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(data.getEmail());
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("danpr080704@gmail.com");
        mailMessage.setText("To confirm your account, please click here : "
                + "http://localhost:8080/auth/confirm-signup?token=" + confirmationToken.getToken());
        emailSenderService.sendEmail(mailMessage);

        return ok().build();
    }

    @GetMapping("/confirm-signup")
    public void confirmRegistration(HttpServletResponse response, @RequestParam("token") String token) throws IOException {
        ConfirmationToken confirmationToken = confirmationTokenService.findByToken(token).orElseThrow();

        if (confirmationTokenService.ifExpired(confirmationToken)) {
            response.sendError(400);
            return;
        }

        User user = confirmationToken.getUser();
        user.setEnabled(true);
        userService.updateUser(user);
        confirmationTokenService.deleteByToken(confirmationToken.getToken());

        response.sendRedirect("http://localhost:3000/login");
    }

    @PostMapping("/login")
    public void signIn(@Valid @RequestBody AuthenticationRequest data,
                       @CookieValue(name = "refreshToken", required = false) String refreshToken,
                       HttpServletResponse response) throws IOException {
        User user = userService.findUserByEmail(data.getEmail()).orElseThrow(() -> new NoSuchElementException("No such user with this email"));
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), data.getPassword(), user.getAuthorities()));
        }
        catch (BadCredentialsException ex) {
            response.sendError(400, "Incorrect password");
            return;
        }
        refreshTokenService.deleteToken(refreshToken);

        createTokenCookies(response, jwtTokenProvider.generateJwtToken(user), refreshTokenService.createToken(user).getToken());
        response.getWriter().print(user.getUsername());
    }

    @PostMapping("/logout")
    public void logout(@CookieValue("accessToken") String accessToken, HttpServletResponse response) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        refreshTokenService.deleteToken(userService.findUserByUsername(username).orElseThrow());
        invalidAccessTokenRepository.save(new InvalidAccessToken(username, accessToken, jwtTokenProvider.getExpiration(accessToken)));
        deleteTokenCookies(response);
    }

    @PostMapping("/renew-access-token")
    public void renewAccessToken(@CookieValue("refreshToken") String token, HttpServletResponse response) throws IOException {
        RefreshToken refreshToken = refreshTokenService.findByToken(token).orElseThrow();
        if (refreshTokenService.ifNonExpired(refreshToken)) {
            refreshTokenService.updateToken(refreshToken);
            createTokenCookies(response, jwtTokenProvider.generateJwtToken(refreshToken.getUser()), refreshToken.getToken());
        }
        else {
            response.sendError(401);
            deleteTokenCookies(response);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@CookieValue("accessToken") String accessToken, @Valid @RequestBody ChangePasswordRequest data) {
        User user = userService.findUserByUsername(getCurrentUsername()).orElseThrow();
        if (user.getProvider() != AuthProvider.local)
            return badRequest().build();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(getCurrentUsername(), data.getOldPassword()));
        }
        catch (BadCredentialsException ex) {
            return badRequest().body("Incorrect password");
        }

        user.setPassword(bCryptPasswordEncoder.encode(data.getNewPassword()));
        userService.updateUser(user);
        invalidAccessTokenRepository.save(new InvalidAccessToken(getCurrentUsername(), accessToken, jwtTokenProvider.getExpiration(accessToken)));
        return ok().build();
    }

    @PostMapping("/change-username")
    public ResponseEntity<String> changeUsernameForOAuth(@CookieValue("accessToken") String accessToken,
                                                         @RequestParam("newUsername") String newUsername) throws UserAlreadyExistException {
        User user = userService.findUserByUsername(getCurrentUsername()).orElseThrow(() -> new UserAlreadyExistException("This nickname is already taken"));
        user.setUsername(newUsername);
        userService.updateUser(user);
        invalidAccessTokenRepository.save(new InvalidAccessToken(getCurrentUsername(), accessToken, jwtTokenProvider.getExpiration(accessToken)));
        return ok().build();
    }

    @PostMapping("/reset-password")
    public void resetPassword(@Email @RequestParam("email") String email) {
        String newPassword = RandomStringUtils.random(15, true, true);
        String confirmationToken = confirmationTokenService.
                createConfirmationToken(userService.findUserByEmail(email).orElseThrow(
                        () -> new NoSuchElementException("No such user with this username"))).getToken();

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(email);
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("danpr080704@gmail.com");
        mailMessage.setText("Your new password will be : " + newPassword +
                "\nTo reset your password, please click here : " +
                "http://localhost:8080/auth/confirm-reset-password?token=" + confirmationToken +
                "&password=" + bCryptPasswordEncoder.encode(newPassword));

        emailSenderService.sendEmail(mailMessage);
    }

    @GetMapping("/confirm-reset-password")
    public void confirmResetPassword(HttpServletResponse response,
                                     @RequestParam("token") String token,
                                     @RequestParam("password") @Size(min = 8, max = 20) String password) throws IOException {
        ConfirmationToken confirmationToken = confirmationTokenService.findByToken(token).orElseThrow();

        if (confirmationTokenService.ifExpired(confirmationToken)) {
            response.sendError(SC_BAD_REQUEST);
            return;
        }

        User user = confirmationToken.getUser();
        user.setPassword(password);
        userService.updateUser(user);
        confirmationTokenService.deleteByToken(confirmationToken.getToken());

        response.sendRedirect("http://localhost:3000/login");
    }
}
