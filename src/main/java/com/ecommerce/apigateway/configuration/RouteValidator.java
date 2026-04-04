package com.ecommerce.apigateway.configuration;

import java.util.List;

import org.springframework.stereotype.Component;

import com.ecommerce.apigateway.dto.RouteRoleRule;

@Component
public class RouteValidator {

	public static List<RouteRoleRule> rules = List.of(
			new RouteRoleRule("/products", "POST", "ROLE_ADMIN"),
			new RouteRoleRule("/products", "DELETE", "ROLE_ADMIN")
	);
	
}
