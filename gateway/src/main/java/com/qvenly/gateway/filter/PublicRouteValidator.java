package com.qvenly.gateway.filter;

import com.qvenly.gateway.dto.PublicRoute;
import com.qvenly.gateway.security.SecurityProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class PublicRouteValidator {

    private final List<PublicRoute> routes;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public PublicRouteValidator(SecurityProperties properties) {
        this.routes = properties.getPublicRoutes();
    }

    public boolean isPublic(String path, String method) {
        return routes.stream().anyMatch(r ->
                matcher.match(r.path(), path) &&
                        (r.method().equals("*") || r.method().equalsIgnoreCase(method))
        );
    }
}