package com.example.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${security.jwt.token.secret-key}")
    private String secretKey;

    @Value("${security.jwt.accessToken.expire-length}")
    private int accessTokenExpiration;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String generateJwtToken(Authentication authentication) {
        Claims claims = Jwts.claims().setSubject(((UserDetails) authentication.getPrincipal()).getUsername());
        claims.put("roles", authentication.getAuthorities());
        claims.put("username", ((UserDetails) authentication.getPrincipal()).getUsername());

        Date now = new Date();
        Date validity = new Date(now.getTime() + accessTokenExpiration);

        System.out.println(validity);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .compact();
    }

    public String getUsername(String authToken) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) throws MalformedJwtException, ExpiredJwtException {
        Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        return true;

//        try {
//            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
//            return authentication.getPrincipal().equals(getUsername(token));
//        } catch (SignatureException e) {
//            logger.error("Invalid JWT signature: {}", e.getMessage());
//        } catch (MalformedJwtException e) {
//            logger.error("Invalid JWT token: {}", e.getMessage());
//        } catch (ExpiredJwtException e) {
//            logger.error("JWT token is expired: {}", e.getMessage());
//        } catch (UnsupportedJwtException e) {
//            logger.error("JWT token is unsupported: {}", e.getMessage());
//        } catch (IllegalArgumentException e) {
//            logger.error("JWT claims string is empty: {}", e.getMessage());
//        }

        //return false;
    }
}
