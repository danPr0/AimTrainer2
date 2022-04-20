package com.example.security.oauth2;

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

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        if (response.isCommitted()) {
            logger.debug("Response has already been committed.");
            return;
        }

        GoogleOAuth2UserInfo oAuth2UserInfo =
                new GoogleOAuth2UserInfo(((OAuth2AuthenticationToken) authentication).getPrincipal().getAttributes());

        UserDetails user = userService.findUserByEmail(oAuth2UserInfo.getEmail()).orElseThrow();
        System.out.println(authentication.getPrincipal().toString());

        String accessToken = jwtTokenProvider.generateJwtToken(user);
        refreshTokenService.deleteToken(user.getUsername());
        String refreshToken = refreshTokenService.createToken(user.getUsername()).getToken();

        String uri = UriComponentsBuilder.fromUriString("http://localhost:3000/oauth2-login")
                .queryParam("username", user.getUsername())
                        .queryParam("accessToken", accessToken)
                                .queryParam("refreshToken", refreshToken).build().toUriString();
        response.sendRedirect(uri);
    }
}
