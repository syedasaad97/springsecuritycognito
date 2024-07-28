package com.zephyrus.auth.security.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.zephyrus.auth.security.filter.AwsCognitoIdTokenProcessor;
import com.zephyrus.auth.security.filter.AwsCognitoJwtAuthenticationFilter;
import com.zephyrus.auth.util.AWSConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.*;

import java.net.MalformedURLException;
import java.net.URL;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

@Configuration
@Import(AWSConfig.class)
@ConditionalOnClass({AwsCognitoJwtAuthenticationFilter.class, AwsCognitoIdTokenProcessor.class})
public class CognitoJwtAutoConfiguration {

    @Bean
    @Scope(value = "request", proxyMode = ScopedProxyMode.TARGET_CLASS)
    public CognitoJwtIdTokenCredentialsHolder awsCognitoCredentialsHolder() {
        return new CognitoJwtIdTokenCredentialsHolder();
    }


    @Bean
    public CognitoJwtAuthenticationProvider jwtAuthenticationProvider() {
        return new CognitoJwtAuthenticationProvider();
    }


    @Autowired(required = true)
    private AWSConfig jwtConfiguration;

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(jwtConfiguration.getConnectionTimeout(), jwtConfiguration.getReadTimeout());
        //https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json.
        URL jwkSetURL = new URL(jwtConfiguration.getJwkUrl());
        //Creates the JSON Web Key (JWK)
        JWKSource keySource = new RemoteJWKSet(jwkSetURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }

}