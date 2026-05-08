package com.qvenly.gateway.security;

public record RoutePermission(String path, String method, String role) {
}