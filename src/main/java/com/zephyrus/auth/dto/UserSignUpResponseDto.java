/**
 * 
 */
package com.zephyrus.auth.dto;


public class UserSignUpResponseDto {
	private String username;
	private String userCreatedDate;
	private String lastModifiedDate;
	private boolean enabled;
	private String userStatus;
	private String password;
	private String email;
	private String responseMessage;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getUserCreatedDate() {
		return userCreatedDate;
	}

	public void setUserCreatedDate(String userCreatedDate) {
		this.userCreatedDate = userCreatedDate;
	}

	public String getLastModifiedDate() {
		return lastModifiedDate;
	}

	public void setLastModifiedDate(String lastModifiedDate) {
		this.lastModifiedDate = lastModifiedDate;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getUserStatus() {
		return userStatus;
	}

	public void setUserStatus(String userStatus) {
		this.userStatus = userStatus;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getResponseMessage() {
		return responseMessage;
	}

	public void setResponseMessage(String responseMessage) {
		this.responseMessage = responseMessage;
	}
}
