package com.qvenly.gateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

@Slf4j
@Component
public class AuthResponseCookieFilter implements GlobalFilter, Ordered {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DataBufferFactory bufferFactory = new DefaultDataBufferFactory();

    private static final List<String> AUTH_PATHS = List.of("/auth/login", "/auth/register");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Solo interceptar login y register
        boolean isAuthPath = AUTH_PATHS.stream().anyMatch(path::equals);
        if (!isAuthPath) {
            return chain.filter(exchange);
        }

        ServerHttpResponse originalResponse = exchange.getResponse();
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (body instanceof Flux) {
                    Flux<? extends DataBuffer> fluxBody = (Flux<? extends DataBuffer>) body;
                    return super.writeWith(fluxBody.map(dataBuffer -> {
                        byte[] content = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(content);

                        try {
                            String bodyStr = new String(content, StandardCharsets.UTF_8);
                            JsonNode root = objectMapper.readTree(bodyStr);
                            JsonNode data = root.path("data");

                            if (!data.isMissingNode()) {
                                String token = data.path("token").asText(null);
                                String refreshToken = data.path("refreshToken").asText(null);

                                if (token != null && !token.equals("null")) {
                                    // Agregar cookies HttpOnly desde el gateway
                                    originalResponse.addCookie(
                                            ResponseCookie.from("access_token", token)
                                                    .httpOnly(true)
                                                    .secure(false)
                                                    .path("/")
                                                    .maxAge(Duration.ofDays(1))
                                                    .sameSite("Lax")
                                                    .build()
                                    );
                                }

                                if (refreshToken != null && !refreshToken.equals("null")) {
                                    originalResponse.addCookie(
                                            ResponseCookie.from("refresh_token", refreshToken)
                                                    .httpOnly(true)
                                                    .secure(false)
                                                    .path("/")
                                                    .maxAge(Duration.ofDays(7))
                                                    .sameSite("Lax")
                                                    .build()
                                    );
                                }

                                // Eliminar tokens del body
                                JsonNode modifiedData = objectMapper.readTree(bodyStr);
                                ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                        .remove("token");
                                ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                        .remove("refreshToken");

                                byte[] modifiedContent = objectMapper.writeValueAsBytes(modifiedData);
                                originalResponse.getHeaders().setContentLength(modifiedContent.length);
                                return bufferFactory.wrap(modifiedContent);
                            }
                        } catch (Exception e) {
                            log.error("Error procesando respuesta auth: {}", e.getMessage());
                        }

                        return bufferFactory.wrap(content);
                    }));
                }
                return super.writeWith(body);
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    @Override
    public int getOrder() {
        return -2;
    }
}