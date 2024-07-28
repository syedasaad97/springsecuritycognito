package com.zephyrus.auth.security;

import com.zephyrus.auth.security.config.CustomAuthenticationProvider;
import com.zephyrus.auth.security.filter.AwsCognitoJwtAuthenticationFilter;
import com.zephyrus.auth.security.filter.RestAccessDeniedHandler;
import com.zephyrus.auth.security.filter.SecurityAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.HttpMethod.*;


@Configuration
@EnableWebSecurity
@EnableAutoConfiguration()
public class WebSecurityConfiguration {

    private final AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter;

    private final CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    public WebSecurityConfiguration(@Lazy AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter, CustomAuthenticationProvider customAuthenticationProvider) {
        this.awsCognitoJwtAuthenticationFilter = awsCognitoJwtAuthenticationFilter;
        this.customAuthenticationProvider = customAuthenticationProvider;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authenticationManager(authManager(http))
                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/c-auth/user/login").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new SecurityAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler()))
                .addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(corsFilter(), ExceptionTranslationFilter.class);

        return http.build();
    }


    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider);
        return authenticationManagerBuilder.build();
    }



    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private CorsFilter corsFilter() {
        /*
         CORS requests are managed only if headers Origin and Access-Control-Request-Method are available on OPTIONS requests
         (this filter is simply ignored in other cases).

         This filter can be used as a replacement for the @Cors annotation.
        */
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader(ORIGIN);
        config.addAllowedHeader(CONTENT_TYPE);
        config.addAllowedHeader(ACCEPT);
        config.addAllowedHeader(AUTHORIZATION);
        config.addAllowedMethod(GET);
        config.addAllowedMethod(PUT);
        config.addAllowedMethod(POST);
        config.addAllowedMethod(OPTIONS);
        config.addAllowedMethod(DELETE);
        config.addAllowedMethod(PATCH);
        config.setMaxAge(3600L);
        source.registerCorsConfiguration("/v2/api-docs", config);
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(corsConfigurationSource());
    }
}
