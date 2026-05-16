package com.qvenly.gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Servicio de validación y extracción de claims JWT en el API Gateway.
 *
 * <p>Es una versión reducida del {@code JwtService} del auth-service: <strong>no genera
 * tokens</strong>, solo los valida y lee. Esto sigue el principio de responsabilidad única:
 * el auth-service es el único emisor de tokens; el Gateway solo los verifica.</p>
 *
 * <p>Comparte el mismo secreto ({@code jwt.secret}) que el auth-service, por lo que
 * ambos deben tener configurado el mismo valor en sus respectivos {@code application.yaml}.
 * El secreto debe estar codificado en Base64 y tener mínimo 256 bits de entropía.</p>
 *
 * <p>Uso en la cadena de filtros:</p>
 * <ul>
 *   <li>{@link com.qvenly.gateway.filter.JwtAuthenticationFilter} usa {@link #isTokenValid(String)}
 *       para decidir si la petición puede pasar.</li>
 *   <li>{@link com.qvenly.gateway.filter.JwtAuthenticationFilter} usa {@link #extractAllClaims(String)}
 *       para obtener el email y rol del usuario y añadirlos como cabeceras.</li>
 * </ul>
 *
 * @author Leidy Martinez
 * @version 1.0
 * @see com.qvenly.gateway.filter.JwtAuthenticationFilter
 */
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * Construye la clave HMAC decodificando el secreto Base64 configurado.
     *
     * <p>Se llama en cada operación para evitar mantener estado mutable,
     * aunque en un escenario de alta carga se podría cachear.</p>
     *
     * @return clave secreta HMAC lista para verificar firmas JWT
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Parsea y devuelve todos los claims del payload del token JWT.
     *
     * <p>Verifica implícitamente la firma y la fecha de expiración al parsear.
     * Lanza una excepción de {@code io.jsonwebtoken} si el token es inválido,
     * malformado o ha expirado.</p>
     *
     * @param token token JWT compacto a parsear
     * @return objeto {@link Claims} con todos los claims del payload
     * @throws io.jsonwebtoken.JwtException si el token es inválido o no puede verificarse
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Verifica si un token JWT es válido (firma correcta y no expirado).
     *
     * <p>Internamente intenta parsear el token con {@link #extractAllClaims(String)}.
     * Si el parseo falla por cualquier razón (firma inválida, token expirado, token
     * malformado), devuelve {@code false} en lugar de propagar la excepción.</p>
     *
     * <p>Este enfoque simplifica el código de los filtros, que solo necesitan
     * evaluar un booleano sin manejar múltiples tipos de excepción JWT.</p>
     *
     * @param token token JWT a validar
     * @return {@code true} si el token es válido y no ha expirado; {@code false} en caso contrario
     */
    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extrae el correo electrónico del usuario desde el subject del token JWT.
     *
     * @param token token JWT del que extraer el email
     * @return correo electrónico del usuario autenticado
     * @throws io.jsonwebtoken.JwtException si el token es inválido
     */
    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extrae el rol del usuario desde el claim {@code role} del token JWT.
     *
     * <p>El claim {@code role} es añadido por el auth-service durante la generación
     * del token en el login y registro. Su valor es el nombre del rol principal
     * del usuario (ej. {@code "USER"}, {@code "ADMIN"}).</p>
     *
     * @param token token JWT del que extraer el rol
     * @return nombre del rol del usuario, o {@code null} si el token no contiene el claim
     * @throws io.jsonwebtoken.JwtException si el token es inválido
     */
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }
}