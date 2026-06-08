package com.qvenly.gateway.security;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

/**
 * Registro de permisos que evalúa si un rol tiene acceso a una ruta y método HTTP.
 *
 * <p>Carga las reglas de {@link SecurityProperties} al inicializarse y las aplica
 * en cada petición a través de {@link com.qvenly.gateway.filter.AuthorizationFilter}.
 * La comparación de rutas usa {@link AntPathMatcher} para soportar wildcards
 * (ej. {@code /api/events/**} cubre {@code /api/events/1}, {@code /api/events/1/tickets}, etc.).</p>
 *
 * <p>La comparación del rol es insensible a mayúsculas/minúsculas para mayor robustez.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see SecurityProperties
 * @see RoutePermission
 */
@Component
public class PermissionRegistry {

    private final List<RoutePermission> permissions;
    private final AntPathMatcher matcher = new AntPathMatcher();

    /**
     * Construye el registro cargando las reglas de permisos desde la configuración.
     *
     * @param props propiedades de seguridad leídas desde {@code application.yaml}
     */
    public PermissionRegistry(SecurityProperties props) {
        this.permissions = props.getPermissions();
    }

    /**
     * Evalúa si el rol dado tiene permiso para acceder a la ruta y método indicados.
     *
     * <p>Devuelve {@code true} si existe al menos una regla en {@code security.permissions}
     * que coincida con los tres criterios: ruta (patrón Ant), método HTTP y rol.</p>
     *
     * @param path   ruta de la petición (ej. {@code /api/events/42})
     * @param method método HTTP de la petición (ej. {@code GET}, {@code POST})
     * @param role   rol del usuario extraído del token JWT (cabecera {@code X-Rol})
     * @return {@code true} si el acceso está permitido; {@code false} en caso contrario
     */
    public boolean isAllowed(String path, String method, String role) {
        return permissions.stream().anyMatch(p ->
                matcher.match(p.path(), path) &&
                        (p.method().equals("*") || p.method().equalsIgnoreCase(method)) &&
                        p.role().equalsIgnoreCase(role)
        );
    }
}