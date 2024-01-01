package io.security.basic.config;

import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")
                        .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                        .anyRequest()
                        .authenticated()
                )
                .formLogin((formLogin) -> formLogin
//                        .loginPage("/loginPage")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .usernameParameter("userId")
                                .passwordParameter("passwd")
                                .loginProcessingUrl("/login_proc")
                                .successHandler((request, response, authentication) -> {
                                    RequestCache requestCache = new HttpSessionRequestCache();
                                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                                    String redirectUrl = savedRequest.getRedirectUrl();
                                    response.sendRedirect(redirectUrl);
//                                    System.out.println("authentication = " + authentication.getName());
//                                    response.sendRedirect("/");
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
                ).sessionManagement((sessionManagement) -> sessionManagement
                        .sessionFixation().changeSessionId()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                ).exceptionHandling((exceptionHandling) -> exceptionHandling
//                        .authenticationEntryPoint((request, response, authException) -> {
//                            response.sendRedirect("/login");
//                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendRedirect("/denied");
                        })
                );

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        return http.build();
    }

    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER").build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, sys, admin);
    }
}
