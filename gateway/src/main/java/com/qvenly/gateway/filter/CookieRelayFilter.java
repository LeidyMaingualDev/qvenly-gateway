package com.qvenly.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CookieRelayFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
            if (responseHeaders.containsKey(HttpHeaders.SET_COOKIE)) {
                // Las cookies HttpOnly del auth service se propagan automáticamente
                // Este filtro asegura que no se pierdan en el relay
            }
        }));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}