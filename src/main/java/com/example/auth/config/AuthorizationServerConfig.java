package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Order(1) // Ensure this runs before default security
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            AuthorizationServerSettings authServerSettings
    ) throws Exception {

        // Apply default OAuth2 Authorization Server security
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // ✅ Required for password grant
        http.authenticationManager(authenticationManager);

        // Disable CSRF for token endpoint (important!)
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token"));

        // Optional: allow form login for testing
        http.formLogin(Customizer.withDefaults());

        return http.build();
    }
}
