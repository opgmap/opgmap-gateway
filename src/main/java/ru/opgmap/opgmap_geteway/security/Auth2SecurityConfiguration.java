package ru.opgmap.opgmap_geteway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;
import ru.opgmap.opgmap_geteway.security.filter.global.AuthConfiguration;

@EnableWebFluxSecurity
@RequiredArgsConstructor
public class Auth2SecurityConfiguration {

    private final AuthConfiguration authConfiguration;

    private final WebFilter auth2JwtProxyFilter;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.cors().disable()
                .authorizeExchange(authorize -> authorize
                        // routes to oAuth2 authentication server are permitted
                        .pathMatchers("/login/oauth2/**").permitAll()
                        .pathMatchers("/resources/**").permitAll()
                        // routes to Eureka discovery server are permitted
                        .pathMatchers("/eureka/**").permitAll()
                        // other routes not allowed
                        .anyExchange().authenticated()
                ).addFilterAt(auth2JwtProxyFilter, SecurityWebFiltersOrder.LAST)
                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);
        return http.build();
    }

}
