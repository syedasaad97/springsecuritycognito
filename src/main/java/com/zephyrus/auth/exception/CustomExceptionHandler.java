package com.zephyrus.auth.exception;

import com.zephyrus.auth.dto.ResponseDto;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Arrays;

@ControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler({BadRequestException.class})
    protected ResponseEntity<ResponseDto> handleException(BadRequestException bre) {
        return new ResponseEntity<>(new ResponseDto(bre.getMessage(), true), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({BaseException.class})
    protected ResponseEntity<ResponseDto> handleException(BaseException ae) {
        return new ResponseEntity<>(new ResponseDto(ae.getMessage(), true), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler({ConstraintViolationException.class})
    protected ResponseEntity<ResponseDto> handleException(ConstraintViolationException cve) {
        return new ResponseEntity<>(new ResponseDto<>(Arrays.asList(cve.getMessage().split(", ")), true), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler({AuthenticationException.class, CognitoException.class})
    public ResponseEntity<ResponseDto> handleIOException(CognitoException e) {
        return new ResponseEntity<>(new ResponseDto<>(Arrays.asList(e.getMessage().split(",")), true), HttpStatus.FORBIDDEN);
    }

    public ResponseDto handleJwtException(CognitoException e) {
        ResponseDto responseDto = new ResponseDto(Arrays.asList(e.getErrorMessage().split(",")), true);
        return responseDto;
    }
}