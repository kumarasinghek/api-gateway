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
		System.out.println("JWT FILTER HIT");
		String path = exchange.getRequest().getURI().getPath();
		if(path.startsWith("/api/auth")) {
			return chain.filter(exchange);
		}
		
		String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}
		
		String token = authHeader.substring(7);
		String role = jwtService.extractRole(token);
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

        try {
            String email = jwtService.extractUsername(token);
            if (email == null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
	}
	
}
