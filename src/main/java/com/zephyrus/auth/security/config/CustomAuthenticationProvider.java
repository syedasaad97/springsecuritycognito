/**
 * 
 */
package com.zephyrus.auth.security.config;

import com.zephyrus.auth.dto.AuthenticationRequestDto;
import com.zephyrus.auth.security.bean.SpringSecurityUser;
import com.zephyrus.auth.security.service.CognitoAuthenticationService;
import com.zephyrus.auth.util.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Custom Authentication that manipulates the logic to call the authentication with Cognito.
 * @author asaad
 * @version
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	CognitoAuthenticationService cognitoService;


	@Override
	public Authentication authenticate(Authentication authentication) {
		AuthenticationRequestDto authenticationRequest = null;
		if(null != authentication) {
			authenticationRequest = new AuthenticationRequestDto();
			Map <String,String> credentials = (Map<String, String>) authentication.getCredentials();
			authenticationRequest.setNewPassword(credentials.get(Constants.NEW_PASS_WORD_KEY));
			authenticationRequest.setPassword(credentials.get(Constants.PASS_WORD_KEY));
			authenticationRequest.setUsername(authentication.getName());
			authenticationRequest.setClientName(credentials.get(Constants.CLIENT_NAME));

			SpringSecurityUser userAuthenticated = cognitoService.authenticate(authenticationRequest);
			if (userAuthenticated != null) {
				Map <String, String> authenticatedCredentials = new HashMap<>();
				authenticatedCredentials.put(Constants.ACCESS_TOKEN_KEY, userAuthenticated.getAccessToken());
				authenticatedCredentials.put(Constants.EXPIRES_IN_KEY, userAuthenticated.getExpiresIn().toString());
//				authenticatedCredentials.put(Constants.ID_TOKEN_KEY, userAuthenticated.getIdToken());
				authenticatedCredentials.put(Constants.PASS_WORD_KEY, userAuthenticated.getPassword());
				authenticatedCredentials.put(Constants.REFRESH_TOKEN_KEY, userAuthenticated.getRefreshToken());
				authenticatedCredentials.put(Constants.TOKEN_TYPE_KEY, userAuthenticated.getTokenType());
				authenticatedCredentials.put(Constants.USERNAME,userAuthenticated.getUsername());
				return new UsernamePasswordAuthenticationToken(
						authenticatedCredentials, authenticatedCredentials, userAuthenticated.getAuthorities());
			} else {
				return null;
			}
		}else {
			throw new UsernameNotFoundException(String.format("No appUser found with username '%s'.", ""));
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(
				UsernamePasswordAuthenticationToken.class);
	}
	
	
}

