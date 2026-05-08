package com.qvenly.gateway.filter;

import com.qvenly.gateway.security.PermissionRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationFilter implements GlobalFilter, Ordered {

    private final PermissionRegistry permissionRegistry;
    private final ErrorResponseWriter errorWriter;
    private final PublicRouteValidator publicRoutes;

    public AuthorizationFilter(PermissionRegistry permissionRegistry,
                               ErrorResponseWriter errorWriter,
                               PublicRouteValidator publicRoutes) {
        this.permissionRegistry = permissionRegistry;
        this.errorWriter = errorWriter;
        this.publicRoutes = publicRoutes;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().name();

        if (publicRoutes.isPublic(path, method)) {
            return chain.filter(exchange);
        }

        String role = exchange.getRequest().getHeaders().getFirst("X-Rol");
        if (role == null || role.isBlank()) {
            return errorWriter.forbidden(exchange, "Rol no encontrado en cabeceras");
        }

        if (!permissionRegistry.isAllowed(path, method, role)) {
            log.info("Authorization check → Path: {}, Method: {}, Role: {}", path, method, role);
            return errorWriter.forbidden(exchange, "No tienes permisos");
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 2;
    }
}