package az.itstep.ts.util;


import az.itstep.ts.model.JwtTokenParameter;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.impl.DefaultClock;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;

@Slf4j
public class JwtTokenValidator {

    private Clock clock = DefaultClock.INSTANCE;

    private final JwtTokenParameter tokenParameter;
    private final JwtTokenUtil tokenUtil;

    public JwtTokenValidator(JwtTokenParameter tokenParameter){
        this.tokenParameter = tokenParameter;
        this.tokenUtil = new JwtTokenUtil(tokenParameter.getSecret());
    }

    public boolean validaToken(String token, UserDetails userDetails){
        String username = tokenUtil.getUsernameFromToken(token);
        return Objects.equals(username, userDetails.getUsername()) && !isTokenExpired(token);
    }

    public boolean canTokenBeRefreshed(String token){
        return !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token){
        return tokenUtil.getExpirationDateFromToken(token).before(clock.now());
    }

}
