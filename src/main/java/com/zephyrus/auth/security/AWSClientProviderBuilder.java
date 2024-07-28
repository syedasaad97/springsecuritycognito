/**
 *
 */
package com.zephyrus.auth.security;

import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.zephyrus.auth.security.config.AwsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


@Component
public class AWSClientProviderBuilder {


    @Value("${aws.region}")
    private String region;

    private AWSCognitoIdentityProvider cognitoIdentityProvider;
    private ClasspathPropertiesFileCredentialsProvider propertiesFileCredentialsProvider;


    private void initCommonInfo() {
        if (null == propertiesFileCredentialsProvider) {
            propertiesFileCredentialsProvider = new ClasspathPropertiesFileCredentialsProvider();
        }
    }

    public AWSCognitoIdentityProvider getAWSCognitoIdentityClient() {
        if (null == cognitoIdentityProvider) {
            initCommonInfo();

            cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(propertiesFileCredentialsProvider)
                    .withRegion(region)
                    .build();
        }

        return cognitoIdentityProvider;
    }

}
