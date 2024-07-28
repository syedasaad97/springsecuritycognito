/**
 * 
 */
package com.zephyrus.auth.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zephyrus.auth.dto.ResponseDto;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.sql.Date;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * utility service class that contains the logic
 * @author asaad
 * @version 

 */
@Component
public class UtilsService {

	private static RestTemplate restTemplate;
	private static ObjectMapper objectMapper;

	public static HttpServletResponse addResponseHeaders(ServletResponse res) {

		HttpServletResponse httpResponse = (HttpServletResponse) res;

		httpResponse.setHeader("Access-Control-Allow-Origin", "*");
		httpResponse.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
		httpResponse.setHeader("Access-Control-Max-Age", "3600");
		httpResponse.setHeader("Access-Control-Allow-Credentials", "true");
		httpResponse.setHeader("Access-Control-Allow-Headers", "content-type,Authorization");
		return httpResponse;
	}

	public static Date convertStringToDate(String date, String format) throws ParseException {
		java.util.Date utilDate= new SimpleDateFormat(format).parse(date);
		Date sqlDate = new Date(utilDate.getTime());
		return sqlDate;  
	}

	public static String convertDateToString(java.util.Date date, String format) {
		String dateString = null;
		if(null != date) {
			DateFormat df = new SimpleDateFormat(format);
			dateString = df.format(date);
		}
		
		return dateString;
	}

	public static boolean isValidDate(String date, String format) {
        boolean valid = false;
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        	LocalDate.parse(date, formatter);
        	valid = true;
        	
        } catch (Exception e) {
            valid = false;
        }
        
        return valid;
    }
	
	public static boolean isStateValid(String state) {
		CharSequence inputStr = state;
		Pattern pattern = Pattern
				.compile("AL|AK|AR|AZ|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY|al|ak|ar|az|ca|co|ct|dc|de|fl|ga|hi|ia|id|il|in|ks|ky|la|ma|md|me|mi|mn|mo|ms|mt|nc|nd|ne|nh|nj|nm|nv|ny|oh|ok|or|pa|ri|sc|sd|tn|tx|ut|va|vt|wa|wi|wv|wy");
		Matcher matcher = pattern.matcher(inputStr);
		if (matcher.matches()) {
			return true;
		} else {
			return false;
		}
	}

	public static boolean hasSqllInjectionCharacters(String text) {
		CharSequence inputStr = text;
		Pattern pattern = Pattern
				.compile("^[^\\'\\{\\}\\\\\\;\\$]*$");
		Matcher matcher = pattern.matcher(inputStr);
		if (matcher.matches()) {
			return false;
		} else {
			return true;
		}

	}

	private static HttpEntity getHttpEntity(Object dto) {
		Map<String, String> headerValues = new HashMap<>();
		headerValues.put("Content-Type", "application/json");
		HttpHeaders headers = generateHttpHeader(headerValues);
		return new HttpEntity<>(dto, headers);
	}

	private static HttpHeaders generateHttpHeader(Map<String, String> headerValues) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		for (String key : headers.keySet())
			headers.add(key, headerValues.get(key));

		return headers;
	}

	public static <T> T performServiceOperation(Map<String, Object> requestInfo, HttpMethod method, final TypeReference<T> type, Object... param){
		try{
			ResponseEntity<ResponseDto> response = performExternalServiceOperation(requestInfo, method, param);
			return objectMapper.convertValue(Objects.requireNonNull(response.getBody()).getResponse(), type);
		} catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}

	private static ResponseEntity<ResponseDto> performExternalServiceOperation(Map<String, Object> requestInfo, HttpMethod method, Object... param) {
		HttpEntity httpEntity = getHttpEntity(requestInfo.get("dto"));
		return restTemplate.exchange((String) requestInfo.get("url"), method, httpEntity, ResponseDto.class, param);
	}

	public static ResponseEntity<ResponseDto> updateExternalService(String url, String mobileToken, String email) {
		HttpEntity httpEntity = UtilsService.getHttpEntity(null);
		return restTemplate.exchange(url, HttpMethod.PUT, httpEntity, ResponseDto.class, mobileToken,email);
	}

	public static void removeNullElements(Set<Long>... ids){
		for (Set<Long> id : ids) id.removeAll(Collections.singleton(null));
	}

	@PostConstruct
	public void createRestTemplate(){
		restTemplate = new RestTemplate();
		objectMapper = new ObjectMapper();
	}
}
