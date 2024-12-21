package com.rafo.app.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(org.springframework.web.server.ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        // Reenviar el encabezado Authorization si está presente
        HttpHeaders headers = exchange.getRequest().getHeaders();
        if (headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            exchange.getRequest().mutate()
                    .header(HttpHeaders.AUTHORIZATION, authHeader)
                    .build();
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1; // Alta prioridad
    }
}
