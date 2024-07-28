
package com.zephyrus.auth.util;


public class Constants {

	
	private Constants() {
		
	}
	public static final String PASS_WORD_KEY ="password";
	public static final String NEW_PASS_WORD_KEY = "newPassword";
	public static final String ACCESS_TOKEN_KEY = "accessToken";
	public static final String EXPIRES_IN_KEY = "expiresIn";
	public static final String TOKEN_TYPE_KEY = "tokenType";
	public static final String REFRESH_TOKEN_KEY = "refreshToken";
	public static final String ID_TOKEN_KEY = "idToken";
	public static final String CLIENT_NAME = "clientName";
	public static final String NEW_PASS_WORD = "NEW_PASSWORD";
	public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
	public static final String NEW_PASS_WORD_REQUIRED = "NEW_PASSWORD_REQUIRED";
	public static final String PASS_WORD = "PASSWORD";
	public static final String USERNAME = "USERNAME";
	public static final String EMAIL_REGEX = "^(^\\w+([\\.-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$)?";
	public static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";
	public static final String SESSION_USER = "user";

}
