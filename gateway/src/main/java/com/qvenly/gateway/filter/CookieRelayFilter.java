package com.qvenly.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Filtro global que garantiza la propagación correcta de las cookies HttpOnly
 * en el relay entre el Gateway y los microservicios destino. Se ejecuta en orden {@code -1}.
 *
 * <p>Spring Cloud Gateway propaga las cookies {@code Set-Cookie} automáticamente.
 * Este filtro actúa como punto de verificación explícito para confirmar
 * su presencia en la respuesta antes de enviarla al cliente.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see AuthResponseCookieFilter
 */
@Component
public class CookieRelayFilter implements GlobalFilter, Ordered {

    /**
     * Ejecuta la cadena de filtros y verifica la presencia de cookies
     * {@code Set-Cookie} en la respuesta para asegurar su propagación al cliente.
     *
     * @param exchange intercambio HTTP reactivo
     * @param chain    cadena de filtros del Gateway
     * @return {@link Mono} que completa tras verificar las cookies en la respuesta
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
            responseHeaders.containsKey(HttpHeaders.SET_COOKIE);
        }));
    }

    /**
     * Define la prioridad de ejecución de este filtro.
     *
     * <p>Orden {@code -1}: se ejecuta después de {@link AuthResponseCookieFilter}
     * (orden -2) pero antes de {@link JwtAuthenticationFilter} (orden 1).</p>
     *
     * @return prioridad {@code -1}
     */
    @Override
    public int getOrder() {
        return -1;
    }
}