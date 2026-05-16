package com.qvenly.gateway.dto;

/**
 * Record inmutable que representa una ruta pública del Gateway, es decir,
 * una ruta que no requiere autenticación JWT para ser accedida.
 *
 * <p>Las rutas públicas se definen en {@code application.yaml} bajo la clave
 * {@code security.public-routes} y son cargadas por {@link com.qvenly.gateway.security.SecurityProperties}.
 * Ejemplo de configuración:</p>
 * <pre>{@code
 * security:
 *   public-routes:
 *     - path: /auth/login
 *       method: POST
 *     - path: /auth/register
 *       method: POST
 *     - path: /actuator/**
 *       method: "*"
 * }</pre>
 *
 * <p>El campo {@code path} soporta patrones Ant (ej. {@code /auth/**}, {@code /public/**})
 * gracias al {@link org.springframework.util.AntPathMatcher} usado en
 * {@link com.qvenly.gateway.filter.PublicRouteValidator}.</p>
 *
 * @param path   patrón de ruta (soporta wildcards Ant como {@code /auth/**})
 * @param method método HTTP permitido ({@code GET}, {@code POST}, etc.) o {@code "*"} para cualquiera
 * @author Leidy Martinez
 * @version 1.0
 * @see com.qvenly.gateway.filter.PublicRouteValidator
 */
public record PublicRoute(String path, String method) {
}