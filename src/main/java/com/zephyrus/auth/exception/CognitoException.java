
/**
 * 
 */
package com.zephyrus.auth.exception;

public class CognitoException extends BaseRuntimeException{
	/**Generated Serial VersuiUID*/
	private static final long serialVersionUID = 5840532488004509747L;

	private static final String MODULE_CODE = "cognito";
	public static final String GENERIC_EXCEPTION_CODE = "00";
	public static final String INVALID_PASS_WORD_EXCEPTION = "01";
	public static final String ACCESS_TOKEN_MISSING_EXCEPTION = "02";
	public static final String USER_MUST_CHANGE_PASS_WORD_EXCEPTION_CODE = "03";
	public static final String USER_MUST_DO_ANOTHER_CHALLENGE = "04";
	public static final String INVALID_USERNAME_EXCEPTION = "05";
	public static final String INVALID_ACCESS_TOKEN_EXCEPTION = "06";
	public static final String EMAIL_MISSING_EXCEPTION = "07";
	public static final String NO_TOKEN_PROVIDED_EXCEPTION = "08";
	public static final String INVALID_TOKEN_EXCEPTION_CODE = "09";
	public static final String NOT_A_TOKEN_EXCEPTION = "10";
	public static final String USERNAME_MISSING_EXCEPTION = "11";

	private String errorCode;
	private final String errorMessage;

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public CognitoException(String message) {
		super(message);
		errorMessage = message;
    }
}
