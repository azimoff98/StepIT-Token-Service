package az.itstep.ts.util;


import az.itstep.ts.model.JwtTokenParameter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtTokenGenerator {

    private Clock clock = DefaultClock.INSTANCE;

    private final JwtTokenParameter tokenParameter;
    private final JwtTokenUtil tokenUtil;

    public JwtTokenGenerator(JwtTokenParameter parameter){
        this.tokenParameter = parameter;
        this.tokenUtil = new JwtTokenUtil(parameter.getSecret());
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }


    public String refreshToken(String token){
        Date issuedDate = clock.now();
        Date expirationDate = new Date(System.currentTimeMillis() + tokenParameter.getExpiration());

        Claims claims = tokenUtil.getAllClaimsFromToken(token);
        claims.setIssuedAt(issuedDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, tokenParameter.getSecret())
                .compact();
    }

    private String doGenerateToken(Map<String, Object> claims, String subject){
        Date issuedDate = clock.now();
        Date expirationDate = new Date(System.currentTimeMillis() + tokenParameter.getExpiration());

        log.info("Token issued at: {}", issuedDate);
        log.info("Token will expire at: {}", expirationDate);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(issuedDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, tokenParameter.getSecret())
                .compact();
    }

}
