package com.wongweiye.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final JwtEncoder jwtEncoder;
    public JwtUtils(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    //now RS256 Algorithm throw Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.
    //and HS512 generated token use in authenticated required endpoints will return 401 unauthorized
    //RS256 is Asymmetric, use two key, public key and private key on both side
    //HS512 is Symmetric, use one secret on both side
    public String generateJwtToken(Authentication authentication) {
        // https://www.baeldung.com/spring-security-map-authorities-jwt - Map Authorities from JWT, we set up custom claim,
        // depends on the Oauth2.0 authorization servers will return what claims/scopes
        // we can create own JwtGrantedAuthoritiesConverter class to defined any prefix we want and inject it into JwtAuthorizationConverter

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        LocalDateTime dateTime = LocalDateTime.now().plusHours(1);

        Instant now = Instant.now();
        Instant expired = dateTime.toInstant(ZoneOffset.UTC).plusSeconds(3600L);

        // scope is a set of claims in Oauth2 specification
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(expired)
                .subject(userPrincipal.getUsername())
                .claim("scope", scope)
                .claim("role", scope)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

    }

}
