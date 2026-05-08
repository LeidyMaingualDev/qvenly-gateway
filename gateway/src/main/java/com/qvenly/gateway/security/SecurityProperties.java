package com.qvenly.gateway.security;

import com.qvenly.gateway.dto.PublicRoute;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    private List<PublicRoute> publicRoutes = new ArrayList<>();
    private List<RoutePermission> permissions = new ArrayList<>();
}