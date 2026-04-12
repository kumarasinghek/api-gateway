package com.ecommerce.apigateway.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.ecommerce.apigateway.dto.RouteRoleRule;
import com.ecommerce.apigateway.service.JwtService;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered{
	
	@Autowired
	private JwtService jwtService;
	
	@Override
	public int getOrder() {
		return -1;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

	    String path = exchange.getRequest().getURI().getPath();

	    System.out.println("PATH: " + path);

	    // ✅ COMPLETELY SKIP SECURITY FOR AUTH + PUBLIC
	    if (
	        path.contains("/auth") ||   // 🔥 covers /api/auth, /auth, etc
	        path.equals("/login") ||
	        path.equals("/register") ||
	        path.equals("/home") ||
	        path.equals("/products") ||
	        path.startsWith("/products") ||
	        path.startsWith("/css") ||
	        path.startsWith("/images") ||
	        path.startsWith("/orders/cart") ||
	        path.startsWith("/cart") ||
	        path.startsWith("/oauth-success") ||
	        path.startsWith("/orders") ||
	        path.startsWith("/oauth2") ||
	        path.startsWith("/js")
	    ) {
	        return chain.filter(exchange); // 🔥 EXIT EARLY
	    }

	    // 🔐 JWT CHECK
	    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

	    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
	        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
	        return exchange.getResponse().setComplete();
	    }

	    String token = authHeader.substring(7);

	    String role;
	    try {
	        role = jwtService.extractRole(token);
	    } catch (Exception e) {
	        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
	        return exchange.getResponse().setComplete();
	    }

	    // 🔐 ROLE VALIDATION
	    String method = exchange.getRequest().getMethod().name();
	    String urlPath = exchange.getRequest().getURI().getPath();

	    for (RouteRoleRule rule : RouteValidator.rules) {
	        if (urlPath.startsWith(rule.getPath()) && method.equals(rule.getMethod())) {
	            if (!rule.getRole().equals(role)) {
	                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
	                return exchange.getResponse().setComplete();
	            }
	        }
	    }

	    return chain.filter(exchange);
	}
	
}
