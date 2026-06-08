package com.qvenly.gateway.security;

/**
 * Record inmutable que representa una regla de autorización basada en ruta, método y rol.
 *
 * <p>Define qué rol tiene acceso a un determinado endpoint HTTP. Las reglas se configuran
 * en {@code application.yaml} bajo la clave {@code security.permissions} y son cargadas
 * por {@link SecurityProperties}. Ejemplo:</p>
 * <pre>{@code
 * security:
 *   permissions:
 *     - path: /events/**
 *       method: "*"
 *       role: USER
 *     - path: /admin/**
 *       method: "*"
 *       role: ADMIN
 * }</pre>
 *
 * <p>El campo {@code path} soporta patrones Ant. El campo {@code role} se compara
 * sin distinción de mayúsculas/minúsculas en {@link PermissionRegistry#isAllowed}.</p>
 *
 * @param path   patrón de ruta protegida (soporta wildcards Ant)
 * @param method método HTTP ({@code GET}, {@code POST}, etc.) o {@code "*"} para cualquiera
 * @param role   nombre del rol requerido (ej. {@code "USER"}, {@code "ADMIN"})
 * @author Leidy Martinez
 * @version 1.0
 * @see PermissionRegistry
 */
public record RoutePermission(String path, String method, String role) {
}