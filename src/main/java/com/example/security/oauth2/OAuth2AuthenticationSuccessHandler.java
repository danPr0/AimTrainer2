package com.example.security.oauth2;

import com.example.entity.User;
import com.example.security.jwt.JwtTokenProvider;
import com.example.service.RefreshTokenService;
import com.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @Autowired
    OAuth2AuthenticationSuccessHandler(JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService,
                                       UserService userService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
    }

    public Cookie createCookie(String name, String value, Boolean httpOnly, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(path);
        return cookie;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (response.isCommitted()) {
            logger.error("Response has already been committed.");
            return;
        }

        GoogleOAuth2UserInfo oAuth2UserInfo =
                new GoogleOAuth2UserInfo(((OAuth2AuthenticationToken) authentication).getPrincipal().getAttributes());

        User user = userService.findUserByEmail(oAuth2UserInfo.getEmail()).orElseThrow();
        System.out.println(authentication.getPrincipal().toString());
        refreshTokenService.deleteToken(user);

        String uri = UriComponentsBuilder.fromUriString("http://localhost:3000/oauth2-login-response")
                .queryParam("username", user.getUsername())
//                .queryParam("accessToken", jwtTokenProvider.generateJwtToken(user))
//                .queryParam("refreshToken", refreshTokenService.createToken(user).getToken())
                .build().toUriString();
        response.addCookie(createCookie("accessToken", jwtTokenProvider.generateJwtToken(user), true, "/"));
        response.addCookie(createCookie("refreshToken", refreshTokenService.createToken(user).getToken(), true, "/"));
        response.sendRedirect(uri);
    }
}
