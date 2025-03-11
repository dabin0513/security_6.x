package io.spring.security.Security_6.x.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .rememberMe(rememberMe -> rememberMe
                        .alwaysRemember(true)                       // true: 체크박스를 선택하지 않아도 언제든 기억하기 인증을 사용한다.
                        .tokenValiditySeconds(3600)                 // 만료시간: 1시간
                        .userDetailsService(userDetailsService())   // 사용자 정보
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
