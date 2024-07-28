package com.zephyrus.auth.controller;

import com.zephyrus.auth.dto.*;
import com.zephyrus.auth.exception.BadRequestException;
import com.zephyrus.auth.security.config.CognitoJwtAuthentication;
import com.zephyrus.auth.security.service.CognitoAuthenticationService;
import com.zephyrus.auth.util.Constants;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@RequestMapping("c-auth/user")
public class AuthController {

    private final CognitoAuthenticationService authService;


    public AuthController(@Lazy CognitoAuthenticationService authService) {
        this.authService = authService;
    }

    private final Logger classLogger = LoggerFactory.getLogger(this.getClass());


    @Autowired(required = false)
    @Lazy
    private AuthenticationManager authenticationManager;

    /**
     * @param authenticationRequest
     * @return AuthenticationResponse- Token and user details
     */
    @SuppressWarnings("unchecked")
//    @CrossOrigin
    @RequestMapping(method = POST, value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseDto<AuthenticationResponseDto>> authenticationRequest(@Valid @RequestBody AuthenticationRequestDto authenticationRequest) {

        if (authenticationRequest.getNewPassword() == null && authenticationRequest.getPassword() == null) {
            classLogger.error("Cognito Authenticate Service : Password is required");
            throw new BadRequestException("Required password");
        }

        Map<String, String> credentials = new HashMap<>();
        credentials.put(Constants.PASS_WORD_KEY, authenticationRequest.getPassword());
        credentials.put(Constants.NEW_PASS_WORD_KEY, authenticationRequest.getNewPassword());
        Authentication authentication = this.authenticationManager.
                authenticate(
                        new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), credentials));
        authService.authUser(authentication);

        return new ResponseEntity<>(new ResponseDto("User login success", false, authService.authUser(authentication)), HttpStatus.OK);
    }

    /**
     * @param signUpRequest
     * @return UserSignupResponse
     */
    @RequestMapping(value = "/add", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseDto<UserSignUpResponseDto>> signUpRequest(@Valid @RequestBody UserDto signUpRequest) {
        return new ResponseEntity<>(new ResponseDto("User signup success", false, authService.signUp(signUpRequest)), HttpStatus.OK);
    }

}
