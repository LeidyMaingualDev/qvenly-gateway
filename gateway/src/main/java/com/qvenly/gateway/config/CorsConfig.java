package com.qvenly.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Configuración centralizada de CORS (Cross-Origin Resource Sharing) para el API Gateway.
 *
 * <p>Al gestionar CORS en el Gateway, todos los microservicios del ecosistema quedan
 * cubiertos automáticamente, sin necesidad de configurar CORS individualmente en cada uno.</p>
 *
 * <p>Se usa {@link CorsWebFilter} (API reactiva) en lugar del {@code CorsFilter} de servlet,
 * ya que Spring Cloud Gateway está construido sobre WebFlux y no sobre el stack de servlet
 * tradicional. Usar el filtro incorrecto resulta en que las cabeceras CORS no se aplican.</p>
 *
 * <p>Configuración actual:</p>
 * <ul>
 *   <li><strong>Orígenes permitidos</strong>: {@code http://localhost:4200} (frontend Angular)</li>
 *   <li><strong>Métodos permitidos</strong>: todos ({@code *})</li>
 *   <li><strong>Headers permitidos</strong>: todos ({@code *})</li>
 *   <li><strong>Headers expuestos</strong>: todos ({@code *})</li>
 *   <li><strong>Credenciales</strong>: {@code true} — necesario para que el navegador
 *       envíe y reciba cookies HttpOnly en peticiones cross-origin</li>
 *   <li><strong>Max-Age</strong>: 3600 segundos (1 hora) para cachear el preflight</li>
 * </ul>
 *
 * <p><strong>Nota de producción</strong>: reemplazar {@code localhost:4200} por el dominio
 * real del frontend antes de desplegar en producción.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 */
@Configuration
public class CorsConfig {

    /**
     * Registra el filtro reactivo de CORS que aplica a todas las rutas del Gateway ({@code /**}).
     *
     * <p>{@code allowCredentials(true)} es obligatorio cuando el frontend envía cookies
     * HttpOnly (los tokens JWT). Sin este flag, el navegador bloquea las peticiones
     * cross-origin que incluyen credenciales aunque el servidor envíe las cabeceras CORS.</p>
     *
     * @return filtro CORS configurado y listo para integrarse en la cadena reactiva de WebFlux
     */
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowedMethods(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}