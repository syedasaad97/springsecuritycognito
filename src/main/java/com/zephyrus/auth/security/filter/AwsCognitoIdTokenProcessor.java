/**
 * The MIT License (MIT)
 * <p>
 * Copyright (c) 2016-present IxorTalk CVBA
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.zephyrus.auth.security.filter;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.zephyrus.auth.exception.CognitoException;
import com.zephyrus.auth.security.config.CognitoJwtAuthentication;
import com.zephyrus.auth.util.AWSConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class AwsCognitoIdTokenProcessor {


    private static final String INVALID_TOKEN = "Invalid Token";
    private static final String NO_TOKEN_FOUND = "Invalid Action, no token found";

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String EMPTY_STRING = "";


    private static final Logger classLogger = LoggerFactory.getLogger(AWSCognitoIdentityProvider.class);
    @SuppressWarnings("rawtypes")

    private ConfigurableJWTProcessor configurableJWTProcessor;


    @Autowired(required = false)
    private AWSConfig jwtConfiguration;


    private String extractAndDecodeJwt(String token) {
        String tokenResult = token;

        if (token != null && token.startsWith("Bearer ")) {
            tokenResult = token.substring("Bearer ".length());
        }
        return tokenResult;
    }

    @SuppressWarnings("unchecked")
    public Authentication getAuthentication(HttpServletRequest request) throws ParseException, BadJOSEException, JOSEException {
        String idToken = request.getHeader(jwtConfiguration.getHttpHeader());
        if (idToken == null) {
            classLogger.error(NO_TOKEN_FOUND);
            throw new CognitoException("Token not found");
        } else {

            idToken = extractAndDecodeJwt(idToken);
            JWTClaimsSet claimsSet = null;

            /**To verify JWT claims:
             1.Verify that the token is not expired.
             2.The audience (aud) claim should match the app client ID created in the Amazon Cognito user pool.
             3.The issuer (iss) claim should match your user pool. For example, a user pool created in the us-east-1 region will have an iss value of: https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>.
             4.Check the token_use claim.
             5.If you are only accepting the access token in your web APIs, its value must be access.
             6.If you are only using the ID token, its value must be id.
             7.If you are using both ID and access tokens, the token_use claim must be either id or access.
             8.You can now trust the claims inside the token.
             */
            ServletContext servletContext = request.getServletContext();
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
            configurableJWTProcessor = webApplicationContext.getBean(ConfigurableJWTProcessor.class);
            claimsSet = configurableJWTProcessor.process(idToken, null);

            if (!isIssuedCorrectly(claimsSet)) {
                classLogger.error(INVALID_TOKEN);
                throw new CognitoException(String.format("Issuer %s in JWT token doesn't match cognito idp %s", claimsSet.getIssuer(), jwtConfiguration.getCognitoIdentityPoolUrl()));
            }

            if (!isAccessToken(claimsSet)) {
                classLogger.error(CognitoException.INVALID_TOKEN_EXCEPTION_CODE);
                throw new CognitoException("JWT Token doesn't seem to be an Access Token");
            }

            String uuid = claimsSet.getClaims().get("username").toString();

            List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
//                    convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));
            User user = new User(uuid, EMPTY_STRING, grantedAuthorities);


            return new CognitoJwtAuthentication(user, claimsSet, grantedAuthorities);

        }

//
    }

    private boolean isIssuedCorrectly(JWTClaimsSet claimsSet) {
        return claimsSet.getIssuer().equals(jwtConfiguration.getCognitoIdentityPoolUrl());
    }

    private boolean isIdToken(JWTClaimsSet claimsSet) {
        return claimsSet.getClaim("token_use").equals("id");
    }

    private boolean isAccessToken(JWTClaimsSet claimsSet) {
        return claimsSet.getClaim("token_use").equals("access");
    }

    public static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}