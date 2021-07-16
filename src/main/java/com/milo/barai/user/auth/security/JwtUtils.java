package com.milo.barai.user.auth.security;

import com.milo.barai.user.auth.exception.UserAuthErrorCode;
import com.milo.barai.user.auth.exception.UserAuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import static com.milo.barai.user.auth.exception.UserAuthErrorCode.*;

@Slf4j
@Component
public class JwtUtils {

    private final SignatureAlgorithm signing;
    private final long expirationTime;
    private final long refreshExpirationTime;
    private final String secret;


    public JwtUtils(@Value("${jwt.secret}") String secret,
                    @Value("${jwt.expiration.time}") Long expirationTime,
                    @Value("${jwt.expiration.time.refresh.limit}") Long refreshExpirationTime) {
        this.refreshExpirationTime = refreshExpirationTime;
        this.expirationTime = expirationTime;
        this.secret = secret;
        this.signing = SignatureAlgorithm.HS512;
    }

    public String generateToken(Map<String, Object> claims, String username) {

        return Jwts.builder()
                   .setSubject(username)
                   .setClaims(claims)
                   .setIssuedAt(new Date(System.currentTimeMillis()))
                   .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                   .signWith(signing, secret)
                   .compact();
    }

    public String refreshToken(String username, String token) {
        String claimedUsername = getUsernameFromToken(token);

        if (!claimedUsername.equals(username)) {
            log.warn("FAKING ATTEMPT: attempted to login with token from user {}, but supplied user {}", username, claimedUsername);
            throw new UserAuthException(UNAUTHORIZED, "Token does not belong to user " + claimedUsername);
        }

        Date expiration = getExpirationDateFromToken(token);
        if (expiration.after(new Date(System.currentTimeMillis() + refreshExpirationTime))) {
            throw new UserAuthException(FORBIDDEN, "Token refresh time has ran out");
        }

        return Jwts.builder()
                   .setSubject(username)
                   .setClaims(getAllClaimsFromToken(token))
                   .setIssuedAt(new Date(System.currentTimeMillis()))
                   .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                   .signWith(signing, secret)
                   .compact();

    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                   .setSigningKey(secret)
                   .parseClaimsJws(token)
                   .getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }


    public Boolean canTokenBeRefreshed(String token) {
        return (!isTokenExpired(token));
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
