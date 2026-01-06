// package com.example.auth.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;

// @Configuration
// public class UserConfig {

//     @Bean
//     public UserDetailsService userDetailsService() {

//         UserDetails pmUser = User.builder()
//                 .username("pmuser")
//                 .password("{noop}password")
//                 .roles("PM")
//                 .build();

//         UserDetails adminUser = User.builder()
//                 .username("admin")
//                 .password("{noop}admin")
//                 .roles("ADMIN")
//                 .build();

//         return new InMemoryUserDetailsManager(pmUser, adminUser);
//     }
// }
