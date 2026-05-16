package com.qvenly.gateway.security;

import com.qvenly.gateway.dto.PublicRoute;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Bean de configuración que mapea las propiedades de seguridad desde {@code application.yaml}.
 *
 * <p>Actúa como fuente de verdad centralizada para las reglas de acceso del Gateway.
 * Al usar {@code @ConfigurationProperties}, Spring enlaza automáticamente las listas
 * definidas en el YAML con los campos de esta clase, permitiendo modificar las reglas
 * sin recompilar el código.</p>
 *
 * <p>Estructura esperada en {@code application.yaml}:</p>
 * <pre>{@code
 * security:
 *   public-routes:
 *     - path: /auth/**
 *       method: "*"
 *   permissions:
 *     - path: /api/events/**
 *       method: GET
 *       role: USER
 *     - path: /api/admin/**
 *       method: "*"
 *       role: ADMIN
 * }</pre>
 *
 * <p>Esta configuración es consumida por {@link PublicRouteValidator} y
 * {@link PermissionRegistry} para tomar decisiones en los filtros.</p>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see PublicRoute
 * @see RoutePermission
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /**
     * Lista de rutas públicas que no requieren autenticación JWT.
     * Se inicializa como lista vacía para evitar {@code NullPointerException}
     * si no hay rutas públicas configuradas.
     */
    private List<PublicRoute> publicRoutes = new ArrayList<>();

    /**
     * Lista de reglas de autorización por ruta, método y rol.
     * Se inicializa como lista vacía para evitar {@code NullPointerException}
     * si no hay permisos configurados.
     */
    private List<RoutePermission> permissions = new ArrayList<>();
}