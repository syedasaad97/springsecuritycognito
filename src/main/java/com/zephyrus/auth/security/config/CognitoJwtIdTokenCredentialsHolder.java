package com.zephyrus.auth.security.config;

public class CognitoJwtIdTokenCredentialsHolder {

    private String idToken;

    public String getIdToken() {
        return idToken;
    }

    public CognitoJwtIdTokenCredentialsHolder setIdToken(String idToken) {
        this.idToken = idToken;
        return this;
    }


}
