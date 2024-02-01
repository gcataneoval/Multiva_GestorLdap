package mx.m3security.multiva.gestionldap.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	public static final String LOGIN_PATH = "/login";

	@Autowired
	private GestionLdapAuthenticatorProvider authProvider;

	@Autowired
	private RESTAuthenticationSuccessHandler authenticationSuccessHandler;

	@Autowired
	private LoginSuccessHandler loginSuccessHandler;
	@Autowired
	private LoginFail loginFail;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authProvider);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers(
						"/ajax/**",
						"/audio/**",
						"/css/**",
						"/fonts/**",
						"/images/**",
						"/js/**",
						"/json/**",
						"/pug/**",
						"/scss/**",
						"/video/**",
						"/assets/**")
				.permitAll().and().authorizeRequests().antMatchers("/actuator/**", "/actuator","/gestionldap","/error").permitAll().and()
				.authorizeRequests().antMatchers("/users/me").authenticated().and().authorizeRequests()
				.antMatchers("/ldaptoken", "/ldaptoken/**").hasAuthority("ADMIN").and().authorizeRequests()
				.antMatchers("/ldapuser", "/ldapuser/**").hasAuthority("ADMIN").and().authorizeRequests().anyRequest()
				.authenticated().and()
				.formLogin().loginPage(LOGIN_PATH).loginProcessingUrl(LOGIN_PATH).permitAll().and().formLogin()
				.successHandler(authenticationSuccessHandler).successHandler(loginSuccessHandler)
				.failureUrl("/error").and().exceptionHandling()
				.and().logout()
				.logoutSuccessUrl(LOGIN_PATH)
				.invalidateHttpSession(true).deleteCookies("JSESSIONID", "XSRF-TOKEN").permitAll().and().csrf()
				.disable().cors();

	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:8081","http://172.16.16.12:9990"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
		configuration
				.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type", "X-XSRF-TOKEN"));
		configuration.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
