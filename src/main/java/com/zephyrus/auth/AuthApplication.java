package com.zephyrus.auth;

import com.zephyrus.auth.security.filter.AwsCognitoJwtAuthenticationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication
@Configuration
//@ComponentScan("com.zephyrus.auth.security.filter")

public class AuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

	@Bean
	public AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter() {
		return new AwsCognitoJwtAuthenticationFilter();
	}

	@Bean
	public FilterRegistrationBean<AwsCognitoJwtAuthenticationFilter> jwtAuthFilterRegister(AwsCognitoJwtAuthenticationFilter filter) {
		FilterRegistrationBean<AwsCognitoJwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
		registrationBean.setFilter(filter);
		registrationBean.setEnabled(true); // Set as needed
		return registrationBean;
	}

}
