package com.example.security.jwt;

import com.example.repository.InvalidAccessTokenRepository;
import com.example.service.UserService;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
    private final InvalidAccessTokenRepository invalidAccessTokenRepository;
    private final UserService userService;

    @Value("${security.jwt.token.secret-key}")
    private String secretKey;

    @Value("${security.jwt.accessToken.expire-length}")
    private int accessTokenExpiration;

    @Autowired
    public JwtTokenProvider(InvalidAccessTokenRepository invalidAccessTokenRepository, UserService userService) {
        this.invalidAccessTokenRepository = invalidAccessTokenRepository;
        this.userService = userService;
    }

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String generateJwtToken(UserDetails user) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenExpiration);

        System.out.println(validity);

        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public Date getExpiration(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getExpiration();
    }

    public String resolveToken(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "accessToken");
        return (cookie != null) ? cookie.getValue() : null;
    }

    public boolean validateToken(String token) throws JwtException {
        Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        return invalidAccessTokenRepository.findByToken(token).isEmpty();
    }

    public Authentication getAuthentication(String token) {
        String username = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
        UserDetails user = userService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(username, "", user.getAuthorities());
    }
}
