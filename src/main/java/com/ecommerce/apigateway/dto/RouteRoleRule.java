package com.ecommerce.apigateway.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RouteRoleRule {

	private String path;
	private String method;
	private String role;
	
}
