package com.zephyrus.auth.exception;

import com.amazonaws.services.cognitoidp.model.*;

public class ServiceException extends BaseRuntimeException {

    public ServiceException(String errorMessage, Exception e) {
        super(errorMessage);
        if(e instanceof ExpiredCodeException || e instanceof NotAuthorizedException || e instanceof  InvalidParameterException){
            throw new CognitoException(errorMessage);
        }else if(e instanceof CognitoException){
            throw new CognitoException(errorMessage);
        }
        else {
            throw new BaseException("Some error occurred, try again");
        }
    }

}
