package com.wongweiye.security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.wongweiye.security.Jwks;
import com.wongweiye.security.service.UserDetailsServiceImpl;
import com.wongweiye.security.service.UserSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;


// depends on the spring security 6 we are using servlet application or reactive application
// https://docs.spring.io/spring-security/reference/servlet/architecture.html - Servlet overall architecture
// https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html - Servlet Authentication Architecture
// https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html - Authorization Architecture
// https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html - OAuth 2 in spring security 6 
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    UserDetailsServiceImpl userDetailsService;

    UserSecurity userSecurity;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService, UserSecurity userSecurity){
        this.userDetailsService = userDetailsService;
        this.userSecurity = userSecurity;
    }

    private final RSAKey rsaKey;
    {
        rsaKey = Jwks.generateRsa();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(authProvider);
    }

    // Encode means encrypt the password to the format we wanted, here we choose BCrypt
    // refer https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html#authentication-password-storage-dpe
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Below is no password encoder means plain text for process password
    //    @Bean
    //    public static NoOpPasswordEncoder passwordEncoder() {
    //        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    //    }

    // in spring boot 3 and spring security 6, antMatchers has been deprecated, use below way
    // spring security use servlet filter to achieve authentication/authorization
    // spring uses delegatingFilterProxy to bridge spring to java web servlet in filter chain
    // delegatingFilterProxy use FilterChainProxy to manage 0-n securityFilterChain, so we can configure our own securityFilterChain
    // in spring security 6.0.x, security filter chain will load default filters which is 11
    // until this point, if we want to access any of the endpoint on browser, it will prompt login dialog and required username and password to authenticate
    // when set OAuth2ResourceServerConfigurer configure option to jwt(Customizer), we need to either supply a Jwk Set Uri, Jwk decoder instance or JwtDecoder bean
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf( csrf -> csrf.disable() )
                .authorizeHttpRequests( authorize -> authorize
                        .requestMatchers("/api/auth/**").permitAll()
                        //.requestMatchers("/api/test/**").permitAll()
                        .requestMatchers("/h2/**").permitAll()
                        .requestMatchers("/actuator/health/**").permitAll()
//                        .requestMatchers("/v1/listNotes/{userName}").access(userSecurity)
//                        .requestMatchers("/v1/getNotes/{userName}/title/{title}").access(userSecurity)
//                        .requestMatchers("/v1/createNotes/{userName}").access(userSecurity)
//                        .requestMatchers("/v1/deleteNotes/{userName}/title/{title}").access(userSecurity)
                        .anyRequest().authenticated()

                )
                .sessionManagement( s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer( oauth2 -> oauth2.jwt( jwt -> {
                    try {
                        jwt.decoder(jwtDecoder());
                    } catch (JOSEException e) {
                        throw new RuntimeException(e);
                    }
                }) );

        return http.build();

    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        // Before hit request/method endpoints In JwtAuthenticationProvider authenticate method, inside it will use JwtAuthenticationConverter.convert(jwt)
        // to extract authorities from JWT to construct JwtAuthenticationToken and return as AbstractAuthenticationToken we used to return for authenticated,
        // by default it will look for JWT claims name scope or scp, and mapped that claims value like this format prefix SCOPE_ + claims value which will causing error for 403
        // due to method haven't @PreAuthorize("hasAuthority('SCOPE_xxx')"), in RBDC(role based data access) design, we will insert ROLE_xxx into roles table
        // so we need to configure JwtGrantedAuthoritiesConverter setAuthorityPrefix to "", then will map claims value to SimpleGrantedAuthority as ROLE_XXX instead of SCOPE_ROLE_XXX
        // GrantedAuthority will decide which protected resource we can access or not

        // either we do in this way or we can create our own CustomJwtConverter to do mapping by ourselves like
        // JwtAuthenticationProvider.setJwtAuthenticationConverter(new xxxCustomJwtConverter())
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // commented out below when we have added the @PreAuthorize("hasAuthority('SCOPE_xxx')") on the endpoints
        //grantedAuthoritiesConverter.setAuthorityPrefix("");


        JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
        authConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return authConverter;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    // we are using asymmetric key to encrypted and decrypted, here we are using RS256 algorithm to sign the JWT, the current JWA recommend algorithm for generate JWT
    // https://codecurated.com/blog/introduction-to-jwt-jws-jwe-jwa-jwk/
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwks) {
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    JwtDecoder jwtDecoder() throws JOSEException {
        // use this as our JwtDecoder by using the public key we set in configuration class to build and return
        // also this JwtDecoder bean for this oauth2ResourceServer
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

}
