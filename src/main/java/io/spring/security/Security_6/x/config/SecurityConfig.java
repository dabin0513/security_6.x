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
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/loginProc") // 사용자 이름과 비밀번호를 검증할 URL 지정 (Form action)
                        .defaultSuccessUrl("/", true)
                        .failureUrl("/failed")
                        .usernameParameter("userId")
                        .passwordParameter("password")
                        .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                            log.info("authentication: {}", authentication);
                            httpServletResponse.sendRedirect("/home");
                        })
                        .failureHandler((httpServletRequest, httpServletResponse, exception) -> {
                            log.error("exception: {}", exception);
                            httpServletResponse.sendRedirect("/login");
                        })
                        .permitAll()
                );

        return http.build();
    }
}
