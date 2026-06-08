package com.qvenly.gateway.filter;

import com.qvenly.gateway.dto.PublicRoute;
import com.qvenly.gateway.security.SecurityProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

/**
 * Componente que determina si una ruta y método HTTP son de acceso público,
 * es decir, no requieren autenticación JWT.
 *
 * <p>Las rutas públicas se definen en {@code application.yaml} bajo
 * {@code security.public-routes} y son cargadas vía {@link SecurityProperties}.
 * La evaluación usa {@link AntPathMatcher} para soportar patrones Ant
 * (ej. {@code /auth/**} cubre cualquier sub-ruta de {@code /auth}).</p>
 *
 * <p>Es usado tanto por {@link JwtAuthenticationFilter} como por
 * {@link AuthorizationFilter} para cortocircuitar el proceso de validación
 * en rutas que no requieren protección.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see SecurityProperties
 * @see PublicRoute
 */
@Component
public class PublicRouteValidator {

    private final List<PublicRoute> routes;
    private final AntPathMatcher matcher = new AntPathMatcher();

    /**
     * Construye el validador cargando la lista de rutas públicas desde la configuración.
     *
     * @param properties propiedades de seguridad del Gateway
     */
    public PublicRouteValidator(SecurityProperties properties) {
        this.routes = properties.getPublicRoutes();
    }

    /**
     * Evalúa si una combinación de ruta y método HTTP está marcada como pública.
     *
     * <p>Una ruta se considera pública si existe al menos una entrada en
     * {@code security.public-routes} cuyo patrón Ant coincida con el path
     * y cuyo método sea {@code "*"} (cualquiera) o coincida exactamente con
     * el método de la petición (insensible a mayúsculas).</p>
     *
     * @param path   ruta de la petición (ej. {@code /auth/login})
     * @param method método HTTP de la petición (ej. {@code POST})
     * @return {@code true} si la ruta es pública y no requiere JWT; {@code false} si está protegida
     */
    public boolean isPublic(String path, String method) {
        return routes.stream().anyMatch(r ->
                matcher.match(r.path(), path) &&
                        (r.method().equals("*") || r.method().equalsIgnoreCase(method))
        );
    }
}