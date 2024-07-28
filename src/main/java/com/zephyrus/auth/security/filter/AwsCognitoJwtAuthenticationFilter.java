package com.zephyrus.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.zephyrus.auth.dto.ResponseDto;
import com.zephyrus.auth.exception.CognitoException;
import com.zephyrus.auth.exception.CustomExceptionHandler;
import com.zephyrus.auth.security.config.CognitoJwtAuthentication;
import com.zephyrus.auth.security.service.CognitoAuthenticationService;
import com.zephyrus.auth.util.UtilsService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

//@Component
public class AwsCognitoJwtAuthenticationFilter extends OncePerRequestFilter {


    private static final Logger classLogger = LoggerFactory.getLogger(AwsCognitoJwtAuthenticationFilter.class);

    private AwsCognitoIdTokenProcessor awsCognitoIdTokenProcessor;

    @Autowired
    private ApplicationContext appContext;


    private CognitoAuthenticationService cognitoAuthenticationService;

    private static final Integer REFRESH_TIME = 10;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*Loading service class from filter beans*/
        ServletContext servletContext = request.getServletContext();
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
        cognitoAuthenticationService = webApplicationContext.getBean(CognitoAuthenticationService.class);
        awsCognitoIdTokenProcessor = webApplicationContext.getBean(AwsCognitoIdTokenProcessor.class);
        Authentication authentication = null;
        try {
            if(request.getHeader("Authorization")!=null) {
                authentication = awsCognitoIdTokenProcessor.getAuthentication(request);
                checkExpiresToken(((CognitoJwtAuthentication) authentication).getJwtClaimsSet(), authentication.getName(), response);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                String userName = ((CognitoJwtAuthentication) authentication).getUserName();
                CognitoAuthenticationService.logoutUserName = userName;
            }
        } catch (BadJOSEException e) {
            SecurityContextHolder.clearContext();
            classLogger.error(e.getMessage());
            createExceptionResponse(request, response, new CognitoException("Invalid Token"));
            return;
        } catch (CognitoException e) {
            SecurityContextHolder.clearContext();
            classLogger.error(e.getMessage() + " code:" + CognitoException.INVALID_TOKEN_EXCEPTION_CODE);
            createExceptionResponse(request, response, new CognitoException(e.getErrorMessage() + " Error occured in token"));
            return;
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            classLogger.error(e.getMessage() + " code:" + CognitoException.INVALID_TOKEN_EXCEPTION_CODE);
            createExceptionResponse(request, response, new CognitoException(" Error occured in token"));
            return;
        }

        filterChain.doFilter(request, response);

    }


    public void checkExpiresToken(JWTClaimsSet claimsSet, String username, HttpServletResponse response) {
        Date expTime = (Date) claimsSet.getClaim("exp");
        Long rem = (expTime.getTime() - new Date().getTime()) / 60000;
        if (rem <= REFRESH_TIME) {
            cognitoAuthenticationService.generateNewToken(username, response);
        }
    }


    private void createExceptionResponse(ServletRequest request, ServletResponse response, CognitoException exception) throws IOException {
        HttpServletRequest req = (HttpServletRequest) request;
        CustomExceptionHandler exceptionController = null;
        ObjectMapper objMapper = new ObjectMapper();

        //ExceptionController is now accessible because I loaded it manually
        exceptionController = appContext.getBean(CustomExceptionHandler.class);
        //Calls the exceptionController
        ResponseDto responseDto = exceptionController.handleJwtException(exception);
        HttpServletResponse httpResponse = UtilsService.addResponseHeaders(response);
        final HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(httpResponse);
        wrapper.setStatus(HttpStatus.UNAUTHORIZED.value());
        wrapper.setContentType(APPLICATION_JSON_VALUE);
        wrapper.getWriter().println(objMapper.writeValueAsString(responseDto));
        wrapper.getWriter().flush();
    }



}