package com.zephyrus.auth.exception;

public class BaseRuntimeException extends RuntimeException {
    protected String message;

    public BaseRuntimeException() {
    }

    public BaseRuntimeException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
