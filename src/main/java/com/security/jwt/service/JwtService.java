package com.security.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtService {

    @Autowired
    UserInfoService userInfoService;

   private static final String secrets ="fshbhQSJHJOOOOOOOx9010iojkwdkkkfjnjdcnbbnbjjoko";

    public String generateToken(String username){
        Map<String, Object> claims = new HashMap<>();
        UserDetails userDetails = userInfoService.loadUserByUsername(username);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put("roles",roles);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();

//        return Jwts.builder()
//                .claims(claims)
//                .subject(username)
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis()+1000*60*30))
//                .signWith(getSignKey())
//                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Base64.getDecoder().decode(secrets);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public Date extractExpiration(String token ){
        return extractClaims(token, Claims::getExpiration);
    }
    private <T>T extractClaims(String token, Function<Claims, T> claimsResolver) {
       final Claims claims = extractAllClaims(token);
       return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){

        return Jwts.parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
