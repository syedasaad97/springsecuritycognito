package com.zephyrus.auth.security.config;

public interface AwsConfig {

    String getRegion();
    int getConnectionTimeout();
    int getReadTimeout();
    String getJwkUrl();
    String getCognitoIdentityPoolUrl();
    String getHttpHeader();
    String getClientId();
    String getPoolId();
    String getGroup();
}
