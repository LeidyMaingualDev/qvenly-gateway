package com.qvenly.gateway.filter;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

/**
 * Componente utilitario para escribir respuestas de error HTTP estructuradas en el Gateway.
 *
 * <p>Al operar en el contexto reactivo de Spring WebFlux, las respuestas de error
 * no se pueden escribir con las APIs de servlet tradicionales. Este componente
 * encapsula la lógica de serialización manual del JSON y la escritura en el buffer
 * reactivo de la respuesta.</p>
 *
 * <p>Todas las respuestas de error siguen esta estructura JSON:</p>
 * <pre>{@code
 * {
 *   "error": "No autorizado",
 *   "message": "Token requerido",
 *   "timestamp": "2024-01-15T10:30:00"
 * }
 * }</pre>
 *
 * @author Equipo Leidy Martinez
 * @version 1.0
 */
@Component
public class ErrorResponseWriter {

    /**
     * Escribe una respuesta {@code 401 Unauthorized} en el intercambio reactivo.
     *
     * <p>Se usa cuando la petición no incluye token JWT o el token es inválido/expirado.</p>
     *
     * @param exchange intercambio HTTP reactivo sobre el que escribir la respuesta
     * @param message  mensaje descriptivo del error de autenticación
     * @return {@link Mono} que completa al terminar de escribir la respuesta
     */
    public Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        return write(exchange, HttpStatus.UNAUTHORIZED, "No autorizado", message);
    }

    /**
     * Escribe una respuesta {@code 403 Forbidden} en el intercambio reactivo.
     *
     * <p>Se usa cuando el usuario está autenticado pero su rol no tiene permiso
     * para acceder a la ruta solicitada.</p>
     *
     * @param exchange intercambio HTTP reactivo sobre el que escribir la respuesta
     * @param message  mensaje descriptivo del error de autorización
     * @return {@link Mono} que completa al terminar de escribir la respuesta
     */
    public Mono<Void> forbidden(ServerWebExchange exchange, String message) {
        return write(exchange, HttpStatus.FORBIDDEN, "Acceso denegado", message);
    }

    /**
     * Escribe una respuesta de error genérica con el código HTTP, error y mensaje dados.
     *
     * <p>Serializa manualmente el JSON (sin Jackson) para evitar dependencias adicionales
     * y escribe los bytes directamente en el buffer de la respuesta reactiva.</p>
     *
     * @param exchange intercambio HTTP reactivo
     * @param status   código HTTP de la respuesta de error
     * @param error    título corto del error (ej. {@code "No autorizado"})
     * @param message  descripción detallada del error
     * @return {@link Mono} que completa al finalizar la escritura
     */
    public Mono<Void> write(ServerWebExchange exchange,
                            HttpStatus status,
                            String error,
                            String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = """
        {
          "error": "%s",
          "message": "%s",
          "timestamp": "%s"
        }
        """.formatted(error, message, LocalDateTime.now());
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return exchange.getResponse()
                .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }
}