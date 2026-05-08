package com.qvenly.gateway.filter;

import com.qvenly.gateway.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;
    private final PublicRouteValidator publicRoutes;
    private final ErrorResponseWriter errorWriter;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   PublicRouteValidator publicRoutes,
                                   ErrorResponseWriter errorWriter) {
        this.jwtService = jwtService;
        this.publicRoutes = publicRoutes;
        this.errorWriter = errorWriter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().name();

        log.info("JwtAuthenticationFilter - Path: {}, Method: {}", path, method);

        String token = extractTokenFromCookie(exchange);
        if (token == null) {
            String header = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }
        }

        if (publicRoutes.isPublic(path, method)) {
            if (token != null && !token.isBlank() && jwtService.isTokenValid(token)) {
                return chain.filter(buildEnrichedExchange(exchange, token));
            }
            return chain.filter(exchange);
        }

        if (token == null || token.isBlank()) {
            return errorWriter.unauthorized(exchange, "Token requerido");
        }

        if (!jwtService.isTokenValid(token)) {
            return errorWriter.unauthorized(exchange, "Token inválido o expirado");
        }

        return chain.filter(buildEnrichedExchange(exchange, token));
    }

    private ServerWebExchange buildEnrichedExchange(ServerWebExchange exchange, String token) {
        var claims = jwtService.extractAllClaims(token);
        String role = claims.get("role", String.class);
        String email = claims.getSubject();

        return exchange.mutate().request(r -> r
                .header("X-User-Email", email != null ? email : "")
                .header("X-Rol", role != null ? role : "")
        ).build();
    }

    private String extractTokenFromCookie(ServerWebExchange exchange) {
        HttpCookie accessTokenCookie = exchange.getRequest().getCookies().getFirst("access_token");
        if (accessTokenCookie != null) {
            log.info("Token obtenido de cookie access_token");
            return accessTokenCookie.getValue();
        }
        HttpCookie tokenCookie = exchange.getRequest().getCookies().getFirst("token");
        if (tokenCookie != null) {
            log.info("Token obtenido de cookie token");
            return tokenCookie.getValue();
        }
        log.debug("No se encontró cookie");
        return null;
    }

    @Override
    public int getOrder() {
        return 1;
    }
}