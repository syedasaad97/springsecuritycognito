package com.zephyrus.auth.dto;

import java.util.Arrays;
import java.util.List;

public class ResponseDto<T> {

    private List<String> responseMessage;
    private boolean isError;
    private T response;

    public List<String> getResponseMessage() {
        return responseMessage;
    }

    public void setResponseMessage(List<String> responseMessage) {
        this.responseMessage = responseMessage;
    }

    public boolean isError() {
        return isError;
    }

    public void setError(boolean error) {
        isError = error;
    }

    public T getResponse() {
        return response;
    }

    public void setResponse(T response) {
        this.response = response;
    }

    public ResponseDto(String responseMessage, boolean isError) {
        this.responseMessage = Arrays.asList(responseMessage);
        this.isError = isError;
    }

    public ResponseDto(List<String> responseMessage, boolean isError) {
        this.responseMessage = responseMessage;
        this.isError = isError;
    }

    public ResponseDto(String responseMessage, boolean isError, T response) {
        this.responseMessage = Arrays.asList(responseMessage);
        this.isError = isError;
        this.response = response;
    }

    public ResponseDto(List<String> responseMessage, boolean isError, T response) {
        this.responseMessage = responseMessage;
        this.isError = isError;
        this.response = response;
    }

    public ResponseDto(boolean isError, T response) {
        this.isError = isError;
        this.response = response;
    }

}
