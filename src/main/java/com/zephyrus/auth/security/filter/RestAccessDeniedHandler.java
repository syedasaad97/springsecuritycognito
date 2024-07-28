package com.zephyrus.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zephyrus.auth.dto.ResponseDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.Arrays;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //For URL or Role Authotization need to check actual staus
        String accessDeniedExcp = "You are not authorized to access this request";
        ResponseDto responseDto = new ResponseDto( Arrays.asList(accessDeniedExcp.split(",")),true);
        ObjectMapper objMapper = new ObjectMapper();
        final HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response);
        wrapper.setStatus(HttpServletResponse.SC_FORBIDDEN);
        wrapper.setContentType(APPLICATION_JSON_VALUE);
        wrapper.getWriter().println(objMapper.writeValueAsString(responseDto));
        wrapper.getWriter().flush();
    }
}
