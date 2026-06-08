package com.qvenly.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Clase principal de arranque del API Gateway de Qvenly.
 *
 * <p>Este componente actúa como punto de entrada único (<em>single entry point</em>)
 * para todos los microservicios de la plataforma. Sus responsabilidades principales son:</p>
 * <ul>
 *   <li><strong>Enrutamiento reactivo</strong>: redirige cada petición al microservicio
 *       correspondiente usando Spring Cloud Gateway (basado en Project Reactor / WebFlux).</li>
 *   <li><strong>Autenticación JWT</strong>: valida el token en cada petición antes de
 *       reenviarla al servicio destino, sin delegar esa responsabilidad a cada microservicio.</li>
 *   <li><strong>Gestión de cookies HttpOnly</strong>: intercepta las respuestas de login y
 *       registro para extraer los tokens JWT del body y convertirlos en cookies seguras,
 *       ocultándolos del código JavaScript del frontend.</li>
 *   <li><strong>Autorización por rol</strong>: verifica que el rol del usuario (extraído del
 *       JWT) tenga permisos sobre la ruta y método solicitado.</li>
 *   <li><strong>CORS centralizado</strong>: gestiona las cabeceras CORS para todos los
 *       servicios desde un único punto de configuración.</li>
 * </ul>
 *
 * <p>Al estar basado en Spring WebFlux, todo el procesamiento es <strong>no bloqueante
 * y reactivo</strong>, lo que lo hace adecuado para alto volumen de peticiones concurrentes.</p>
 *
 * <h2>Cadena de filtros (orden de ejecución)</h2>
 * <pre>
 * Petición entrante
 *   │
 *   ├─ [orden -2] AuthResponseCookieFilter   → intercepta respuestas de /auth/login y /auth/register
 *   ├─ [orden -1] CookieRelayFilter          → propaga cookies HttpOnly en el relay
 *   ├─ [orden  1] JwtAuthenticationFilter    → valida JWT, enriquece headers (X-User-Email, X-Rol)
 *   ├─ [orden  2] AuthorizationFilter        → verifica permisos por rol y ruta
 *   └─ Microservicio destino
 * </pre>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see com.qvenly.gateway.filter.JwtAuthenticationFilter
 * @see com.qvenly.gateway.filter.AuthorizationFilter
 * @see com.qvenly.gateway.filter.AuthResponseCookieFilter
 */
@SpringBootApplication
public class GatewayApplication {

    /**
     * Punto de entrada de la aplicación Spring Boot del API Gateway.
     *
     * @param args argumentos de línea de comandos pasados al arrancar la JVM
     */
	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

}
