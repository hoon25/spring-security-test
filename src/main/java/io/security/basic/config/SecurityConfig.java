package io.security.basic.config;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest()
                        .authenticated())
                .formLogin((formLogin) -> formLogin
//                        .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler((request, response, authentication) -> {
                                    System.out.println("authentication = " + authentication.getName());
                                    response.sendRedirect("/");
                                })
                                .failureHandler((request, response, exception) -> {
                                    System.out.println("exception = " + exception.getMessage());
                                    response.sendRedirect("/login");
                                })
                                .permitAll()  // 관련 url permit
                )
                .logout((logout) -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .addLogoutHandler((request, response, authentication) -> {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.sendRedirect("/login");
                        })
                        .deleteCookies("JSESSIONID", "remember-me")
                )
                .rememberMe((rememberMe) -> rememberMe
                        .rememberMeParameter("remember")
                        .tokenValiditySeconds(3600)
                        .alwaysRemember(false)
                        .userDetailsService(userDetailsService)
                ).sessionManagement((sessionManagement) -> sessionManagement
                        .sessionFixation().changeSessionId()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                );

        return http.build();
    }
}
