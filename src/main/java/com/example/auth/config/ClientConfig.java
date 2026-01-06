package com.example.auth.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
public class ClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        // USER JWT client (password grant)
        RegisteredClient userClient =
                RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("user-client")
                        .clientSecret("{noop}secret") // MUST use a secret for password grant
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD) // password grant
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .scope("openid")
                        .scope("USER")
                        .build();


        // SERVICE JWT client (client credentials)
        RegisteredClient serviceClient =
                RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("simulation-service")
                        .clientSecret("{noop}secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("ADMIN")
                        .scope("USER")
                        .build();

        return new InMemoryRegisteredClientRepository(userClient, serviceClient);
    }
}
