package com.ecommerce.apigateway.service;

import java.sql.Date;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private String SECRET = "mysecretkeymysecretkeymysecretkey";
		
		public String generateToken(String username) {
			return Jwts.builder()
					.setSubject(username)
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 86400000))
					.signWith(Keys.hmacShaKeyFor(SECRET.getBytes()), SignatureAlgorithm.HS256)
					.compact();
		}
	
		public String extractUsername(String token) {
			
			return Jwts.parserBuilder()
					.setSigningKey(SECRET.getBytes())
					.build()
					.parseClaimsJws(token)
					.getBody()
					.getSubject();
			
	}
	
}
