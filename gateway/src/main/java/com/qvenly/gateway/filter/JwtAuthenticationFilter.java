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

/**
 * Filtro global de autenticación JWT del API Gateway. Se ejecuta en orden {@code 1}.
 *
 * <p>Es el primer filtro de seguridad que procesa la petición entrante. Su responsabilidad
 * es validar el token JWT y, si es válido, enriquecer la petición con las cabeceras
 * {@code X-User-Email} y {@code X-Rol} para que los microservicios destino puedan
 * identificar al usuario sin necesidad de consultar el auth-service.</p>
 *
 * <h2>Fuentes del token JWT (por prioridad)</h2>
 * <ol>
 *   <li>Cookie {@code access_token} (HttpOnly, establecida por {@link AuthResponseCookieFilter})</li>
 *   <li>Cookie {@code token} (compatibilidad con implementaciones anteriores)</li>
 *   <li>Cabecera {@code Authorization: Bearer <token>} (clientes que no soportan cookies)</li>
 * </ol>
 *
 * <h2>Comportamiento según tipo de ruta</h2>
 * <ul>
 *   <li><strong>Ruta pública sin token</strong>: deja pasar la petición sin modificarla.</li>
 *   <li><strong>Ruta pública con token válido</strong>: enriquece la petición con las cabeceras
 *       aunque no sea obligatorio, para que el servicio destino pueda personalizar la respuesta.</li>
 *   <li><strong>Ruta protegida sin token</strong>: devuelve {@code 401 Unauthorized}.</li>
 *   <li><strong>Ruta protegida con token inválido/expirado</strong>: devuelve {@code 401 Unauthorized}.</li>
 *   <li><strong>Ruta protegida con token válido</strong>: enriquece y reenvía la petición.</li>
 * </ul>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see JwtService
 * @see PublicRouteValidator
 * @see AuthorizationFilter
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;
    private final PublicRouteValidator publicRoutes;
    private final ErrorResponseWriter errorWriter;

    /**
     * Construye el filtro con sus dependencias (inyección por constructor para testabilidad).
     *
     * @param jwtService   servicio de validación y extracción de claims JWT
     * @param publicRoutes validador de rutas públicas
     * @param errorWriter  escritor de respuestas de error reactivas
     */
    public JwtAuthenticationFilter(JwtService jwtService,
                                   PublicRouteValidator publicRoutes,
                                   ErrorResponseWriter errorWriter) {
        this.jwtService = jwtService;
        this.publicRoutes = publicRoutes;
        this.errorWriter = errorWriter;
    }

    /**
     * Lógica principal del filtro de autenticación JWT.
     *
     * <p>Extrae el token de cookie o header, evalúa si la ruta requiere autenticación
     * y actúa en consecuencia. Si el token es válido, construye un intercambio enriquecido
     * con las cabeceras del usuario antes de pasarlo al siguiente filtro.</p>
     *
     * @param exchange intercambio HTTP reactivo con la petición y respuesta
     * @param chain    cadena de filtros del Gateway a continuar
     * @return {@link Mono} que completa cuando el filtro (y el resto de la cadena) terminan
     */
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

    /**
     * Construye un nuevo intercambio HTTP enriquecido con las cabeceras del usuario autenticado.
     *
     * <p>Añade:</p>
     * <ul>
     *   <li>{@code X-User-Email}: correo del usuario (subject del JWT)</li>
     *   <li>{@code X-Rol}: rol del usuario (claim {@code role} del JWT)</li>
     * </ul>
     * <p>Estos headers permiten a los microservicios destino identificar al usuario
     * sin necesidad de validar el JWT nuevamente.</p>
     *
     * @param exchange intercambio original
     * @param token    token JWT validado del que se extraen los claims
     * @return nuevo intercambio con las cabeceras de identidad añadidas a la petición
     */
    private ServerWebExchange buildEnrichedExchange(ServerWebExchange exchange, String token) {
        var claims = jwtService.extractAllClaims(token);
        String role = claims.get("role", String.class);
        String email = claims.getSubject();
        String userId = claims.get("userId", String.class);

        return exchange.mutate().request(r -> r
                .header("X-User-Email", email != null ? email : "")
                .header("X-Rol", role != null ? role : "")
                .header("X-User-Id", userId != null ? userId : "")
        ).build();
    }

    /**
     * Extrae el token JWT de las cookies de la petición.
     *
     * <p>Busca primero la cookie {@code access_token} (establecida por
     * {@link AuthResponseCookieFilter} en el login). Si no existe, busca
     * la cookie {@code token} por compatibilidad con versiones anteriores.</p>
     *
     * @param exchange intercambio HTTP del que extraer las cookies
     * @return valor del token JWT si se encontró en alguna cookie; {@code null} en caso contrario
     */
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

    /**
     * Define la prioridad de ejecución de este filtro en la cadena del Gateway.
     *
     * <p>Orden {@code 1}: se ejecuta después de {@link AuthResponseCookieFilter} (orden -2)
     * y {@link CookieRelayFilter} (orden -1), pero antes de {@link AuthorizationFilter} (orden 2).
     * Esto garantiza que cuando {@code AuthorizationFilter} se ejecute, las cabeceras
     * {@code X-Rol} ya están disponibles.</p>
     *
     * @return prioridad {@code 1}
     */
    @Override
    public int getOrder() {
        return 1;
    }
}