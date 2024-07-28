package com.zephyrus.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;


@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationResponseDto {
	private String accessToken;
	private String sessionToken;
	private String expiresIn;
	private String actualDate;
	private String expirationDate;
	private UserDto userData;
	private String username;
	private String message;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getSessionToken() {
		return sessionToken;
	}

	public void setSessionToken(String sessionToken) {
		this.sessionToken = sessionToken;
	}

	public String getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(String expiresIn) {
		this.expiresIn = expiresIn;
	}

	public String getActualDate() {
		return actualDate;
	}

	public void setActualDate(String actualDate) {
		this.actualDate = actualDate;
	}

	public String getExpirationDate() {
		return expirationDate;
	}

	public void setExpirationDate(String expirationDate) {
		this.expirationDate = expirationDate;
	}

	public UserDto getUserData() {
		return userData;
	}

	public void setUserData(UserDto userData) {
		this.userData = userData;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}