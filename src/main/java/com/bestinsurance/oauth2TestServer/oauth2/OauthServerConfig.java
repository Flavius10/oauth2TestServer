package com.bestinsurance.oauth2TestServer.oauth2;

import ch.qos.logback.core.net.server.Client;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.net.ssl.KeyStoreBuilderParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
public class OauthServerConfig {

    private enum Roles{
        ADMIN, FRONT_OFFICE, BACK_OFFICE, CUSTOMER
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        /// Enables OpenID Connect and get the configurer and enable OIDC with default settings
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        /// set the login entry for the exception handling
        http.exceptionHandling((exceptions) ->
                exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                /// Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        http.cors(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        /// Enables cors
        http.cors(Customizer.withDefaults());

        /// Authorize any request
        http.authorizeHttpRequests((authorizeRequests) -> authorizeRequests.anyRequest().authenticated());

        /// Enable oauth2 login and form login
        http.formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration corsConfiguration = new CorsConfiguration();
        List<String> origins = new ArrayList<>();
        origins.add("http://127.0.0.1:8080");
        origins.add("http://127.0.0.1");
        origins.add("http://auth-server");
        origins.add("http://auth-server:9090");

        corsConfiguration.setAllowedOrigins(origins);
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "DELETE"));
        corsConfiguration.setMaxAge(1728000L);
        corsConfiguration.setAllowedHeaders(List.of("Access-Control-Allow-Headers", "Access-Control-Allow-Credentials", "authorization", "x-requested-with"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.validateAllowCredentials();

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }

    @Bean
    public UserDetailsService repoForUsers(){

        UserDetails admin = User.builder().passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                ::encode)
                .username("admin")
                .password("password")
                .roles(Roles.ADMIN.name())
                .build();

        UserDetails fronOffice = User.builder().passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                ::encode)
                .username("fronOffice")
                .password("password")
                .roles(Roles.FRONT_OFFICE.name())
                .build();

        UserDetails backOffice = User.builder().passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                ::encode)
                .username("backOffice")
                .password("password")
                .roles(Roles.BACK_OFFICE.name())
                .build();

        UserDetails customer = User.builder().passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()
                ::encode)
                .username("customer")
                .password("password")
                .roles(Roles.CUSTOMER.name())
                .build();

        return new InMemoryUserDetailsManager(admin, fronOffice, backOffice, customer);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-flavius")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/swagger-ui/oauth2-redirect.html")
                .redirectUri("https://oidcdebugger.com/debug")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource(){

        KeyPair keyPair = generateRsaKey();

        /// That it's used by the user
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        /// That it's used by the client
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();


        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);

    }

    private KeyPair generateRsaKey() {

        KeyPair keyPair;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(){
        return context -> {
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN){
                context.getClaims().claim("roles", context.getPrincipal().getAuthorities());
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


}
