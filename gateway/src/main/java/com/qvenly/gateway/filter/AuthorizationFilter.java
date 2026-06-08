package com.qvenly.gateway.filter;

import com.qvenly.gateway.security.PermissionRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


/**
 * Filtro global de autorización basada en roles del API Gateway. Se ejecuta en orden {@code 2}.
 *
 * <p>Se ejecuta <strong>después</strong> de {@link JwtAuthenticationFilter} (orden 1),
 * que ya ha validado el JWT y añadido la cabecera {@code X-Rol} a la petición.
 * Este filtro lee esa cabecera y consulta el {@link PermissionRegistry} para determinar
 * si el rol tiene acceso a la ruta y método solicitado.</p>
 *
 * <h2>Lógica de decisión</h2>
 * <ol>
 *   <li>Si la ruta es pública → deja pasar sin verificar rol.</li>
 *   <li>Si la cabecera {@code X-Rol} está ausente o vacía → devuelve {@code 403 Forbidden}.</li>
 *   <li>Si el rol no tiene permiso en {@code PermissionRegistry} → devuelve {@code 403 Forbidden}.</li>
 *   <li>Si el rol tiene permiso → deja pasar al microservicio destino.</li>
 * </ol>
 *
 * <p>La separación entre autenticación (¿quién eres?) y autorización (¿qué puedes hacer?)
 * en dos filtros distintos facilita el mantenimiento y permite evolucionar cada capa
 * de forma independiente.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see PermissionRegistry
 * @see JwtAuthenticationFilter
 */
@Slf4j
@Component
public class AuthorizationFilter implements GlobalFilter, Ordered {

    private final PermissionRegistry permissionRegistry;
    private final ErrorResponseWriter errorWriter;
    private final PublicRouteValidator publicRoutes;

    /**
     * Construye el filtro con sus dependencias.
     *
     * @param permissionRegistry registro de permisos por ruta, método y rol
     * @param errorWriter        escritor de respuestas de error reactivas
     * @param publicRoutes       validador de rutas públicas
     */
    public AuthorizationFilter(PermissionRegistry permissionRegistry,
                               ErrorResponseWriter errorWriter,
                               PublicRouteValidator publicRoutes) {
        this.permissionRegistry = permissionRegistry;
        this.errorWriter = errorWriter;
        this.publicRoutes = publicRoutes;
    }

    /**
     * Lógica principal del filtro de autorización por rol.
     *
     * <p>Lee la cabecera {@code X-Rol} inyectada por {@link JwtAuthenticationFilter}
     * y verifica que el rol tenga acceso a la ruta y método solicitado según las
     * reglas definidas en {@code application.yaml}.</p>
     *
     * @param exchange intercambio HTTP reactivo
     * @param chain    cadena de filtros a continuar si la autorización es exitosa
     * @return {@link Mono} que completa cuando el filtro y la cadena terminan,
     *         o al escribir la respuesta de error si el acceso es denegado
     */
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

    /**
     * Define la prioridad de ejecución de este filtro en la cadena del Gateway.
     *
     * <p>Orden {@code 2}: se ejecuta después de {@link JwtAuthenticationFilter} (orden 1),
     * garantizando que la cabecera {@code X-Rol} ya está disponible cuando este filtro
     * la consulta.</p>
     *
     * @return prioridad {@code 2}
     */
    @Override
    public int getOrder() {
        return 2;
    }
}