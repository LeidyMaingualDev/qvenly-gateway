package com.qvenly.gateway.security;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class PermissionRegistry {

    private final List<RoutePermission> permissions;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public PermissionRegistry(SecurityProperties props) {
        this.permissions = props.getPermissions();
    }

    public boolean isAllowed(String path, String method, String role) {
        return permissions.stream().anyMatch(p ->
                matcher.match(p.path(), path) &&
                        (p.method().equals("*") || p.method().equalsIgnoreCase(method)) &&
                        p.role().equalsIgnoreCase(role)
        );
    }
}