package com.zephyrus.auth.dto;

/**
 * Class that contains the authentication request data.
 */
public class AuthenticationRequestDto {

//    @NotNull(message = "Username cannot be null")
//    @Pattern(regexp= Constants.EMAIL_REGEX,message="Email is not valid")
    private String username;
//    @NotNull(message = "Password cannot be null")
//    @Pattern(regexp = Constants.PASSWORD_REGEX ,message = "At least One Upper case, One Digit and One Special Character")
//    @Size(min = 8 ,max = 20,message = "Length Should Be Atleast 8 Characters Long and At-most 20 characters and At least One Upper case, One Digit and One Special Character")
    private String password;
    private String clientName;
    private String newPassword;
    private String accessToken;
    private String mobileSessionId;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getMobileSessionId() {
        return mobileSessionId;
    }

    public void setMobileSessionId(String mobileSessionId) {
        this.mobileSessionId = mobileSessionId;
    }
}