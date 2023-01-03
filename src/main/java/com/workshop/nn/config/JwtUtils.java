package com.workshop.nn.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {

    private String jwtSigningKey = "secret";


    // 1000 => 1초
    private final long VALIDATEIEM = 1000 * 60 * 60 * 9; // 9시간


    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims,userDetails);
    }

    public String generateToken(UserDetails userDetails, Map<String,Object> claims){
        return createToken(claims,userDetails);
    }

    private String createToken(Map<String,Object> claims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(claims) // 빈 map을 만들어줘야함
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // 발행시간
                .setExpiration(new Date(System.currentTimeMillis() + VALIDATEIEM))
                // 만료시간
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey)
                // 알고리즘 방식, 키
                .compact();
    }


    public boolean hasClaim(String token, String claimName){
        final Claims claims = extractAllClaim(token);
        return claims.get(claimName) != null;
    }


    // 정보 추출용 메소드
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts.parser().setSigningKey(jwtSigningKey).
                parseClaimsJws(token).getBody();
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaim(String token) {
        return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
    }



    // 토큰에서 아이디 추출
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // 토큰에서 만료시간 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 유효시간 체크
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 토큰이 유효한지 체크
    public boolean isTokenValidation(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
