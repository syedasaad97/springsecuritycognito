package com.zephyrus.auth.dto;

import java.io.Serializable;

public class ResetPasswordDto implements Serializable {
	private String username;
	private String password;
	private String confirmationCode;
	private String oldPassword;
	private String accessToken;
	private String deliveryMedium;
	private String message;

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

	public String getConfirmationCode() {
		return confirmationCode;
	}

	public void setConfirmationCode(String confirmationCode) {
		this.confirmationCode = confirmationCode;
	}

	public String getOldPassword() {
		return oldPassword;
	}

	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getDeliveryMedium() {
		return deliveryMedium;
	}

	public void setDeliveryMedium(String deliveryMedium) {
		this.deliveryMedium = deliveryMedium;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
