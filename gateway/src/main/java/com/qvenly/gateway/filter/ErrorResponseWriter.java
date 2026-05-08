package com.qvenly.gateway.filter;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Component
public class ErrorResponseWriter {

    public Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        return write(exchange, HttpStatus.UNAUTHORIZED, "No autorizado", message);
    }

    public Mono<Void> forbidden(ServerWebExchange exchange, String message) {
        return write(exchange, HttpStatus.FORBIDDEN, "Acceso denegado", message);
    }

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