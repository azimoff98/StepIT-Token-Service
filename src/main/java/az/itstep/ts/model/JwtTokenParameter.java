package az.itstep.ts.model;


import lombok.Data;

@Data
public class JwtTokenParameter {

    private String secret;
    private Long expiration;

    public JwtTokenParameter(String secret) {
        this.secret = secret;
    }

    public JwtTokenParameter(String secret, Long expiration) {
        this.secret = secret;
        this.expiration = expiration;
    }
}
