package com.rafo.app.ms_security.security;


import com.rafo.app.ms_security.util.Constants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, Constants.ENDPOINT_USERS_AUTHENTICATE).permitAll() // Permitir acceso público
                        .requestMatchers(HttpMethod.POST, Constants.ENDPOINT_USERS).hasRole(Constants.ROLE_ADMIN) // Solo ADMIN puede crear usuarios
                        .requestMatchers(HttpMethod.GET, Constants.ENDPOINT_USERS).authenticated() // Requiere autenticación
                        .requestMatchers(HttpMethod.GET, Constants.ENDPOINT_USERS_USERNAME).permitAll() // GET público para usuarios específicos
                        .anyRequest().authenticated() // Todo lo demás requiere autenticación
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // Agregar el filtro JWT
                .httpBasic(withDefaults()); // Autenticación básica habilitada para otros endpoints

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
                .username(Constants.USERNAME_BASIC)
                .password(new BCryptPasswordEncoder().encode(Constants.PASSWORD_BASIC)) // Contraseña cifrada
                .roles(Constants.ROLE_ADMIN) // Rol asignado
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Bean para cifrado de contraseñas
    }

}
