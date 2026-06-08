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
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
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


/**
 * Filtro global que intercepta las respuestas de autenticación y convierte los tokens JWT
 * del body en cookies HttpOnly, protegiéndolos del acceso de JavaScript en el frontend.
 * Se ejecuta en orden {@code -2} (el primero en envolver la respuesta).
 *
 * <h2>Problema que resuelve</h2>
 * <p>Si los tokens JWT se devuelven en el cuerpo JSON de la respuesta, el código JavaScript
 * del frontend puede acceder a ellos mediante {@code localStorage} o {@code sessionStorage},
 * lo que los expone a ataques XSS (Cross-Site Scripting). Al moverlos a cookies
 * {@code HttpOnly}, solo el navegador puede leerlas y enviarlas automáticamente,
 * sin que ningún script pueda acceder a su valor.</p>
 *
 * <h2>Rutas interceptadas</h2>
 * <ul>
 *   <li>{@code /auth/login}</li>
 *   <li>{@code /auth/register}</li>
 * </ul>
 *
 * <h2>Transformación aplicada</h2>
 * <ol>
 *   <li>Intercepta el body de la respuesta usando un {@link ServerHttpResponseDecorator}.</li>
 *   <li>Parsea el JSON y extrae los campos {@code data.token} y {@code data.refreshToken}.</li>
 *   <li>Crea dos cookies HttpOnly:
 *     <ul>
 *       <li>{@code access_token}: duración 1 día, {@code SameSite=Lax}</li>
 *       <li>{@code refresh_token}: duración 7 días, {@code SameSite=Lax}</li>
 *     </ul>
 *   </li>
 *   <li>Elimina los campos {@code token} y {@code refreshToken} del body JSON
 *       para que no viajen en la respuesta visible al cliente.</li>
 *   <li>Ajusta el {@code Content-Length} al nuevo tamaño del body modificado.</li>
 * </ol>
 *
 * <p><strong>Nota sobre {@code secure=false}</strong>: en producción con HTTPS,
 * cambiar a {@code secure(true)} para garantizar que las cookies solo se envíen
 * en conexiones cifradas.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see JwtAuthenticationFilter
 */
@Slf4j
@Component
public class AuthResponseCookieFilter implements GlobalFilter, Ordered {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DataBufferFactory bufferFactory = new DefaultDataBufferFactory();

    /** Rutas cuyas respuestas son interceptadas para extraer y convertir los tokens en cookies. */
    private static final List<String> AUTH_PATHS = List.of("/auth/login", "/auth/register");

    /**
     * Lógica principal del filtro. Envuelve la respuesta con un decorator que intercepta
     * el cuerpo y realiza la transformación token → cookie.
     *
     * <p>Para rutas que no son de autenticación, la petición pasa sin modificaciones.</p>
     *
     * @param exchange intercambio HTTP reactivo
     * @param chain    cadena de filtros del Gateway
     * @return {@link Mono} que completa cuando la respuesta (posiblemente modificada) es enviada
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        boolean isAuthPath = AUTH_PATHS.stream().anyMatch(path::equals);
        if (!isAuthPath) {
            return chain.filter(exchange);
        }

        ServerHttpResponse originalResponse = exchange.getResponse();
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

            /**
             * Intercepta la escritura del body de la respuesta.
             *
             * <p>Acumula todos los chunks con {@link DataBufferUtils#join} antes de procesar,
             * evitando el error de JSON incompleto que ocurría con el procesamiento chunk a chunk.</p>
             *
             * @param body publisher de buffers con el contenido de la respuesta
             * @return Mono que completa cuando el body modificado es enviado al cliente
             */
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                return DataBufferUtils.join(Flux.from(body))
                        .flatMap(dataBuffer -> {
                            byte[] content = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(content);
                            DataBufferUtils.release(dataBuffer);

                            try {
                                String bodyStr = new String(content, StandardCharsets.UTF_8);
                                JsonNode root = objectMapper.readTree(bodyStr);
                                JsonNode data = root.path("data");

                                if (!data.isMissingNode()) {
                                    String token        = data.path("token").asText(null);
                                    String refreshToken = data.path("refreshToken").asText(null);

                                    // Escribir access_token como cookie HttpOnly
                                    if (token != null && !token.equals("null")) {
                                        originalResponse.addCookie(
                                                ResponseCookie.from("access_token", token)
                                                        .httpOnly(true)
                                                        .secure(false)       // true en producción
                                                        .path("/")
                                                        .maxAge(Duration.ofMinutes(15))
                                                        .sameSite("Lax")
                                                        .build()
                                        );
                                    }

                                    // Escribir refresh_token como cookie HttpOnly
                                    if (refreshToken != null && !refreshToken.equals("null")) {
                                        originalResponse.addCookie(
                                                ResponseCookie.from("refresh_token", refreshToken)
                                                        .httpOnly(true)
                                                        .secure(false)       // true en producción
                                                        .path("/")
                                                        .maxAge(Duration.ofDays(7))
                                                        .sameSite("Lax")
                                                        .build()
                                        );
                                    }

                                    // Eliminar tokens del body — no deben viajar al cliente
                                    JsonNode modifiedData = objectMapper.readTree(bodyStr);
                                    ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                            .remove("token");
                                    ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                            .remove("refreshToken");

                                    byte[] modifiedContent = objectMapper.writeValueAsBytes(modifiedData);
                                    originalResponse.getHeaders().setContentLength(modifiedContent.length);
                                    return super.writeWith(Mono.just(bufferFactory.wrap(modifiedContent)));
                                }

                                // Eliminar tokens del body para no exponerlos al cliente
                                JsonNode modifiedData = objectMapper.readTree(bodyStr);
                                ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                        .remove("token");
                                ((com.fasterxml.jackson.databind.node.ObjectNode) modifiedData.path("data"))
                                        .remove("refreshToken");

                                byte[] modifiedContent = objectMapper.writeValueAsBytes(modifiedData);
                                originalResponse.getHeaders().setContentLength(modifiedContent.length);
                                return bufferFactory.wrap(modifiedContent);
                            }

                            originalResponse.getHeaders().setContentLength(content.length);
                            return super.writeWith(Mono.just(bufferFactory.wrap(content)));
                        });
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    /**
     * Define la prioridad de ejecución de este filtro.
     *
     * <p>Orden {@code -2}: el más bajo (mayor prioridad) de todos los filtros de seguridad,
     * para que el decorator de respuesta esté instalado antes de que cualquier otro
     * filtro procese la petición y su respuesta.</p>
     *
     * @return prioridad {@code -2}
     */
    @Override
    public int getOrder() {
        return -2;
    }
}