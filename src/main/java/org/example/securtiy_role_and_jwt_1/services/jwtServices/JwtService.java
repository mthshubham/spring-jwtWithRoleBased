package org.example.securtiy_role_and_jwt_1.services.jwtServices;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.*;
import java.util.Base64;
import java.util.function.Function;

@Service
public class JwtService {

    private String randomSecretkey;
    public JwtService(){
        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            SecretKey secretKey = keyGenerator.generateKey();
            randomSecretkey=Base64.getEncoder().encodeToString(secretKey.getEncoded());
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }


    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
//                1000 milliseconds= 1second  ,1000*60= 60 second=1 minute ,1000*60*2=2 minute
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 *60 )) // current millisecond+120000 milliscond
//                .signWith(getKey(), SignatureAlgorithm.HS256) // Proper signing method  ( use if using own key )
//                .signWith(randomKey())  // Without signing (use for random generated  key )
                .signWith(randomKey(), SignatureAlgorithm.HS256)
                .compact();
    }

//    By my own key

    private Key getKey() {
        // Use Keys.hmacShaKeyFor for a proper key
        String secretKey = "preetikaShubhamSharmaShupriyaSharmaPriyanshuSharma"; // if we use less long it will generate an error
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

//  or By Automatic Random generate key
    private Key randomKey(){
        byte[] keyBytes = Base64.getDecoder().decode(randomSecretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String decodeUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(randomKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }



    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean validateToken(String jwtToken, UserDetails userDetails) {
        final String userName = decodeUsername(jwtToken);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken));
    }
}





























//
//import io.jsonwebtoken.Jwts;
//import org.springframework.stereotype.Service;
//
//import javax.crypto.spec.SecretKeySpec;
//import java.security.Key;
//import java.util.Base64;
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//
//@Service
//public class JwtService {
//    public String generateToken(String username){
//        Map<String,Object> claims=new HashMap<String,Object>();
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .addClaims(claims)
//                .setSubject( username)
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis()*60*60*2))
//                .signWith(getkey())
//                .compact();
//    }
//
//    private Key getkey(){
//        byte[] keyBytes = Base64.getEncoder().encode("preetikaSharma".getBytes());
//        return new SecretKeySpec(keyBytes, "AES");
//    }
//}
