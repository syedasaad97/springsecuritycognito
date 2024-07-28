/**
 *
 */
package com.zephyrus.auth.security.service;

import com.amazonaws.services.budgets.model.DuplicateRecordException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.zephyrus.auth.dto.*;
import com.zephyrus.auth.exception.BadRequestException;
import com.zephyrus.auth.exception.CognitoException;
import com.zephyrus.auth.exception.ServiceException;
import com.zephyrus.auth.security.AWSClientProviderBuilder;
import com.zephyrus.auth.security.bean.SpringSecurityUser;
import com.zephyrus.auth.util.Constants;
import com.zephyrus.auth.util.UtilsService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CognitoAuthenticationService {


    private final Logger classLogger = LoggerFactory.getLogger(this.getClass());
    public static String logoutUserName = null;


    private final AWSClientProviderBuilder cognitoBuilder;

    @Value("${aws.cognito.clientId}")
    private String clientId;

    @Value("${aws.cognito.poolId}")
    private String poolId;


    @Autowired
    private HttpSession httpSession;

    public CognitoAuthenticationService(AWSClientProviderBuilder cognitoBuilder) {
        this.cognitoBuilder = cognitoBuilder;
    }

    private AWSCognitoIdentityProvider getAmazonCognitoIdentityClient() {
        return cognitoBuilder.getAWSCognitoIdentityClient();
    }

    public AuthenticationResponseDto authUser(Authentication authentication) {
        try {
            String expiresIn = null;
            String token = null;
            String accessToken = null;

            Map<String, String> authenticatedCredentials = (Map<String, String>) authentication.getPrincipal();
            expiresIn = authenticatedCredentials.get(Constants.EXPIRES_IN_KEY);
            accessToken = authenticatedCredentials.get(Constants.ACCESS_TOKEN_KEY);


            return getAuthenticationResponse(token, expiresIn, accessToken);

        } catch (ServiceException e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        } catch (Exception e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        }

    }


    /**
     * authenticating user from cognito
     *
     * @param authenticationRequest
     * @return
     */
    public SpringSecurityUser authenticate(AuthenticationRequestDto authenticationRequest) {
        AuthenticationResultType authenticationResult = null;
        AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
        classLogger.info("Cognito Authenticate Service : User Authenticating , username : {}", authenticationRequest.getUsername());
//		CAuthUser user=userRepository.findByEmail(authenticationRequest.getUsername());
        try {
            final Map<String, String> authParams = new HashMap<>();
            authParams.put(Constants.USERNAME, authenticationRequest.getUsername());
            authParams.put(Constants.PASS_WORD, authenticationRequest.getPassword());

            final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
            authRequest.withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                    .withClientId(clientId)
                    .withUserPoolId(poolId)
                    .withAuthParameters(authParams);

            AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);
            //Has a Challenge
            if (StringUtils.isNotBlank(result.getChallengeName())) {

                //If the challenge is required new Password validates if it has the new password variable.
                if (Constants.NEW_PASS_WORD_REQUIRED.equals(result.getChallengeName())) {

                    if (authenticationRequest.getNewPassword() == null) {
                        throw new CognitoException("User must provide new password");
                    } else {
                        //add the new password to the params map
                        authParams.put(Constants.NEW_PASS_WORD, authenticationRequest.getNewPassword());

                        //populate the challenge response
                        final AdminRespondToAuthChallengeRequest request = new AdminRespondToAuthChallengeRequest();
                        request.withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                                .withChallengeResponses(authParams)
                                .withClientId(clientId)
                                .withUserPoolId(poolId)
                                .withSession(result.getSession());

                        AdminRespondToAuthChallengeResult resultChallenge = cognitoClient.adminRespondToAuthChallenge(request);
                        authenticationResult = resultChallenge.getAuthenticationResult();

                    }
                } else {
                    //has another challenge
                    throw new BadRequestException(result.getChallengeName());
                }

            } else {
                //Doesn't have a challenge
                authenticationResult = result.getAuthenticationResult();
            }
            List<GrantedAuthority> authorities = new ArrayList<>();
            httpSession.setAttribute(Constants.SESSION_USER, authenticationRequest.getUsername());

            httpSession.setAttribute(Constants.SESSION_USER, authenticationRequest.getUsername());
            SpringSecurityUser userAuthenticated = new SpringSecurityUser(authenticationRequest.getUsername(), authenticationRequest.getPassword(), null, null, authorities);
            userAuthenticated.setAccessToken(authenticationResult.getAccessToken());
            userAuthenticated.setExpiresIn(authenticationResult.getExpiresIn());
            userAuthenticated.setTokenType(authenticationResult.getTokenType());
            userAuthenticated.setRefreshToken(authenticationResult.getRefreshToken());
            userAuthenticated.setIdToken(authenticationResult.getIdToken());

            if (classLogger.isInfoEnabled()) {
                classLogger.info("Cognito Authenticate Service : User authenticated username = {}", authenticationRequest.getUsername());
            }

            return userAuthenticated;
        } catch (AWSCognitoIdentityProviderException e) {
            classLogger.error(e.getMessage());
            throw new ServiceException(e.getErrorMessage(), e);
        } catch (Exception e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        }
    }

    public GetUserResult getUserInfo(String accessToken) {
        AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
        try {
            if (StringUtils.isBlank(accessToken)) {
                throw new CognitoException("Access Token not found");
            }
            GetUserRequest userRequest = new GetUserRequest().withAccessToken(accessToken);
            GetUserResult userResult = cognitoClient.getUser(userRequest);

            return userResult;

        } catch (AWSCognitoIdentityProviderException e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getErrorMessage(), e);

        } catch (Exception e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        }

    }

    //    @Transactional
    public UserSignUpResponseDto signUp(UserDto signUpRequest) {
        AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
        classLogger.info("Cognito Authenticate Service : creating user {}", signUpRequest.getEmail());
        try {
            AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
                    .withUserPoolId(poolId)
                    .withUsername(signUpRequest.getUsername())
                    .withUserAttributes(
                            new AttributeType()
                                    .withName("email")
                                    .withValue(signUpRequest.getEmail()),
                            new AttributeType()
                                    .withName("name")
                                    .withValue(signUpRequest.getFirstName() + " " + signUpRequest.getLastName()),
                            new AttributeType()
                                    .withName("phone_number")
                                    .withValue(signUpRequest.getPhoneNumber()),
                            new AttributeType()
                                    .withName("address").withValue(signUpRequest.getAddress()),
                            new AttributeType().withName("email_verified").withValue("true"),
                            new AttributeType().withName("family_name").withValue(signUpRequest.getFamilyName()),
                            new AttributeType().withName("preferred_username").withValue(signUpRequest.getUsername()),
                            new AttributeType().withName("custom:schemaName").withValue(signUpRequest.getSchemaName()))
//                            ,
//                            new AttributeType().withName("phone_number_verified").withValue("true"))
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .withForceAliasCreation(Boolean.FALSE);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(cognitoRequest);
            UserSignUpResponseDto userResult = new UserSignUpResponseDto();
            UserType cognitoUser = createUserResult.getUser();


            userResult.setEmail(signUpRequest.getEmail());
            userResult.setEnabled(cognitoUser.getEnabled());
            userResult.setUserStatus(cognitoUser.getUserStatus());
            userResult.setLastModifiedDate(UtilsService.convertDateToString(cognitoUser.getUserLastModifiedDate(), "MM-dd-yyyy"));
            userResult.setUserCreatedDate(UtilsService.convertDateToString(cognitoUser.getUserCreateDate(), "MM-dd-yyyy"));
            userResult.setResponseMessage("User Signup with temp password");

            classLogger.info("Cognito Authenticate Service : User created {} ", userResult.getEmail());

            return userResult;

        } catch (AWSCognitoIdentityProviderException e) {
            classLogger.error(e.getMessage(), e);
            if (e instanceof UsernameExistsException)
                throw new DuplicateRecordException("user.exist");
            else
                throw new ServiceException(e.getErrorMessage(), e);
        } catch (Exception e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        }

    }

    public AuthenticationResponseDto signUpConfirmation(ResetPasswordDto signUpRequest) {

        AuthenticationResponseDto authenticationResponse = null;
        if (StringUtils.isBlank(signUpRequest.getUsername())) {
            throw new CognitoException("Invalid user name");
        }

        if (StringUtils.isBlank(signUpRequest.getPassword())) {
            throw new CognitoException("Invalid Password");
        }

        if (classLogger.isInfoEnabled()) {
            classLogger.info("Cognito Authenticate Service :confirming signup of user {}", signUpRequest.getUsername());
        }

        try {
            AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
            //First Attempt must attempt signin with temporary password in order to establish session for password change
            Map<String, String> initialParams = new HashMap<>();
            initialParams.put(Constants.USERNAME, signUpRequest.getUsername());
            initialParams.put(Constants.PASS_WORD, signUpRequest.getOldPassword());

            //Initializes the request.
            AdminInitiateAuthRequest initialRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .withAuthParameters(initialParams)
                    .withClientId(clientId)
                    .withUserPoolId(poolId);

            //Invokes the cognito authentication
            AdminInitiateAuthResult initialResponse = cognitoClient.adminInitiateAuth(initialRequest);

            //Validates if it has a new password.
            if (!ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(initialResponse.getChallengeName())) {
                throw new CognitoException(initialResponse.getChallengeName() + " " + "Required");
            }

            Map<String, String> challengeResponses = new HashMap<>();
            challengeResponses.put(Constants.USERNAME, signUpRequest.getUsername());
            challengeResponses.put(Constants.PASS_WORD, signUpRequest.getOldPassword());
            challengeResponses.put(Constants.NEW_PASS_WORD, signUpRequest.getPassword());

            //Initializes the challenge response
            AdminRespondToAuthChallengeRequest finalRequest = new AdminRespondToAuthChallengeRequest()
                    .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                    .withChallengeResponses(challengeResponses)
                    .withClientId(clientId)
                    .withUserPoolId(poolId)
                    .withSession(initialResponse.getSession());

            //Invokes the cognito authentication
            AdminRespondToAuthChallengeResult challengeResponse = cognitoClient.adminRespondToAuthChallenge(finalRequest);

            //Validates if it has another challenge
            if (!StringUtils.isBlank(challengeResponse.getChallengeName())) {
                classLogger.error(challengeResponse.getChallengeName() + " " + CognitoException.USER_MUST_DO_ANOTHER_CHALLENGE);
                throw new CognitoException(challengeResponse.getChallengeName());
            }

//			addUserToGroup(signUpRequest.getUserName(), cognitoConfig.getDeveloperGroup());
            if (challengeResponse.getAuthenticationResult() != null) {
                GetUserResult userBean = getUserInfo(challengeResponse.getAuthenticationResult().getAccessToken());
                authenticationResponse = getAuthenticationResponse(challengeResponse.getAuthenticationResult().getIdToken(), challengeResponse.getAuthenticationResult().getExpiresIn().toString(), challengeResponse.getAuthenticationResult().getAccessToken());

            }

            if (classLogger.isInfoEnabled()) {
                classLogger.info("Cognito Authenticate Service :Sign up confirm successfully for user {} ", signUpRequest.getUsername());
            }

        } catch (AWSCognitoIdentityProviderException e) {
            classLogger.error(e.getMessage(), e);
            throw new CognitoException(e.getMessage()
            );
        } catch (CognitoException cognitoException) {
            throw cognitoException;
        } catch (Exception e) {
            classLogger.error(e.getMessage() + " " + CognitoException.GENERIC_EXCEPTION_CODE);
            throw new CognitoException(e.getMessage());
        }
        return authenticationResponse;

    }


    public void generateNewToken(String userId, HttpServletResponse response) {

        try {
            classLogger.info("Cognito Authenticate Service : started refreshing token");
//            CAuthAccessToken cAuthAccessToken = cAuthAccessTokenRepository.findByUserId(userId);
//            if (cAuthAccessToken != null && cAuthAccessToken.getRefreshToken() != null) {
            AWSCognitoIdentityProvider cognitoClient = getAmazonCognitoIdentityClient();
            final Map<String, String> authParams = new HashMap<>();
//                authParams.put(Constants.REFRESH_TOKEN, cAuthAccessToken.getRefreshToken());

            final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
            authRequest.withAuthFlow(AuthFlowType.REFRESH_TOKEN)
                    .withClientId(clientId)
                    .withUserPoolId(poolId)
                    .withAuthParameters(authParams);

            AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);

            if (result.getAuthenticationResult() != null && StringUtils.isBlank(result.getChallengeName())) {
                String accessToken = result.getAuthenticationResult().getAccessToken();
//                    addOrUpdateAccessToken(userId, accessToken, cAuthAccessToken.getRefreshToken());
                response.addHeader("access_token", accessToken);
                classLogger.info("Cognito Authenticate Service : new token generated");
            }

        } catch (AWSCognitoIdentityProviderException e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getErrorMessage(), e);
        } catch (Exception e) {
            classLogger.error(e.getMessage(), e);
            throw new ServiceException(e.getMessage(), e);
        }
    }

    public AuthenticationResponseDto getAuthenticationResponse(String token, String expiresIn, String accessToken) {
        AuthenticationResponseDto authenticationResponse = new AuthenticationResponseDto();
        try {
            authenticationResponse.setExpiresIn(expiresIn);
            authenticationResponse.setAccessToken(accessToken);
//            authenticationResponse.setUserData(userBean);
            return authenticationResponse;
        } catch (Exception e) {
            classLogger.error(e.getMessage());
            throw new ServiceException(e.getMessage(), e);
        }

    }


}
