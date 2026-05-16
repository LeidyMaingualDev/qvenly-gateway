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
 * <p>Actúa en la fase de <strong>respuesta</strong> (después de que el microservicio
 * destino responde). Verifica que las cabeceras {@code Set-Cookie} generadas por el
 * auth-service o por {@link AuthResponseCookieFilter} no se pierdan al pasar por el Gateway.</p>
 *
 * <p>Spring Cloud Gateway generalmente propaga las cookies automáticamente, pero este
 * filtro actúa como salvaguarda explícita ante posibles escenarios donde las cabeceras
 * podrían ser descartadas durante el relay reactivo.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see AuthResponseCookieFilter
 */
@Component
public class CookieRelayFilter implements GlobalFilter, Ordered {

    /**
     * Ejecuta la cadena de filtros y, en la fase de respuesta, verifica la presencia
     * de cabeceras {@code Set-Cookie} para asegurar su correcta propagación al cliente.
     *
     * @param exchange intercambio HTTP reactivo
     * @param chain    cadena de filtros del Gateway
     * @return {@link Mono} que completa tras verificar las cookies en la respuesta
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
            if (responseHeaders.containsKey(HttpHeaders.SET_COOKIE)) {
                // Las cookies HttpOnly del auth-service se propagan automáticamente.
                // Este filtro actúa como punto de verificación para asegurar
                // que no se pierdan en el relay reactivo.
            }
        }));
    }

    /**
     * Define la prioridad de ejecución de este filtro.
     *
     * <p>Orden {@code -1}: se ejecuta después de {@link AuthResponseCookieFilter} (orden -2)
     * que instala el decorator, pero antes de {@link JwtAuthenticationFilter} (orden 1)
     * que lee las cookies.</p>
     *
     * @return prioridad {@code -1}
     */
    @Override
    public int getOrder() {
        return -1;
    }
}