package com.example.config;

import com.example.security.jwt.JwtTokenFilter;
import com.example.security.jwt.AuthEntryPointJwt;
import com.example.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.service.CustomOAuth2UserService;
import com.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;
import java.security.SecureRandom;
import java.util.Properties;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    public final UserService userService;
    public final DataSource dataSource;
    public final JwtTokenFilter jwtTokenFilter;
    private final AuthEntryPointJwt authEntryPointJwt;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Autowired
    public WebSecurityConfig(UserService userService, DataSource dataSource,
                             JwtTokenFilter jwtTokenFilter, AuthEntryPointJwt authEntryPointJwt,
                             CustomOAuth2UserService customOAuth2UserService,
                             OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                             OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler) {
        this.userService = userService;
        this.dataSource = dataSource;
        this.jwtTokenFilter = jwtTokenFilter;
        this.authEntryPointJwt = authEntryPointJwt;
        this.customOAuth2UserService = customOAuth2UserService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .httpBasic().disable()
                .cors().and()
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                    .antMatchers("/auth/signup", "/auth/login",
                            "/auth/renew-access-token", "/auth/google-login", "oauth2/**").anonymous()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/*").hasRole("USER")
                    .antMatchers("/auth/reset-password", "/auth/confirm-reset-password*",
                            "/auth/confirm-signup*").permitAll()
                    .antMatchers("/auth/*").authenticated()
                    .anyRequest().authenticated().and()
                .oauth2Login()
                    .authorizationEndpoint()
                        .baseUri("/oauth2/authorize").and()
                    .redirectionEndpoint()
                        .baseUri("/oauth2/callback/*").and()
                    .userInfoEndpoint()
                        .userService(customOAuth2UserService).and()
                    .successHandler(oAuth2AuthenticationSuccessHandler)
                    .failureHandler(oAuth2AuthenticationFailureHandler);

        httpSecurity.addFilterAfter(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(15, new SecureRandom());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public JavaMailSenderImpl mailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);

        mailSender.setUsername("danpr080704@gmail.com");
        mailSender.setPassword("tnskwwkkeuyscsyq");

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true");

        return mailSender;
    }
}