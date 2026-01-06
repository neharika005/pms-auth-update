package com.example.auth.config;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(Authentication clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
        // Parent only takes (GrantType, ClientPrincipal, AdditionalParameters)
        super(new AuthorizationGrantType("password"), clientPrincipal, additionalParameters);
        this.scopes = Collections.unmodifiableSet(scopes != null ? scopes : Collections.emptySet());
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}