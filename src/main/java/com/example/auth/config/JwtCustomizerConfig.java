package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class JwtCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            // USER JWT
            if (AuthorizationGrantType.PASSWORD.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claim("token_type", "USER");
                context.getClaims().claim("username", context.getPrincipal().getName());
            }

            // SERVICE JWT
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claim("token_type", "SERVICE");
            }

            // roles
            if (!context.getPrincipal().getAuthorities().isEmpty()) {
                var roles = context.getPrincipal().getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .toList();
                context.getClaims().claim("roles", roles);
            }
        };
    }
}
