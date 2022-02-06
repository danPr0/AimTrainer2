package com.example.config;

import com.example.security.jwt.JwtTokenFilter;
import com.example.security.jwt.AuthEntryPointJwt;
import com.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    public final UserService userService;
    public final DataSource dataSource;
    public final JwtTokenFilter jwtTokenFilter;
    private final AuthEntryPointJwt authEntryPointJwt;

    @Autowired
    public WebSecurityConfig(UserService userService, DataSource dataSource,
                             JwtTokenFilter jwtTokenFilter, AuthEntryPointJwt authEntryPointJwt) {
        this.userService = userService;
        this.dataSource = dataSource;
        this.jwtTokenFilter = jwtTokenFilter;
        this.authEntryPointJwt = authEntryPointJwt;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .httpBasic().disable()
                .cors().and()
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                    .antMatchers("/registration", "/auth/signin").not().fullyAuthenticated()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/*").hasRole("USER")
                    .antMatchers("/auth/**").permitAll()
                .anyRequest().authenticated();

        httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

//                .and()
//                    .formLogin()
//                    .loginProcessingUrl("/perform_login")
//                    .failureForwardUrl("/?result=error")
//                    .successForwardUrl("/?result=success")
////                    .permitAll()
//                    //.failureHandler(authenticationFailureHandler())
//
//
//                .and()
//                    .logout()
//                    .logoutUrl("/perform_logout")

//                .and()
//                    .rememberMe()
//                    .tokenRepository(persistentTokenRepository());
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

//    @Bean
//    public PersistentTokenRepository persistentTokenRepository() {
//        JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
//        //db.setCreateTableOnStartup(true);
//        db.setDataSource(dataSource);
//        return db;
//    }
}
