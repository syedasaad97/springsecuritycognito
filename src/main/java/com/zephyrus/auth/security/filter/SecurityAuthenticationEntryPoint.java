package com.zephyrus.auth.security.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.zephyrus.auth.dto.ResponseDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Arrays;


import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


public class SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

       //For Criterion of user login if password is not in correct format
        String authExc = authException.getMessage().concat(",Credentials may be invalid as per criteria");
        ResponseDto responseDto = new ResponseDto(true,Arrays.asList(authExc.split(",")));
        ObjectMapper objMapper = new ObjectMapper();
        HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response);
        wrapper.setStatus(SC_BAD_REQUEST);
        wrapper.setContentType(APPLICATION_JSON_VALUE);
        wrapper.getWriter().println(objMapper.writeValueAsString(responseDto));
        wrapper.getWriter().flush();
    }
}
