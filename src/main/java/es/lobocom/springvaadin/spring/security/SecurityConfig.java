package es.lobocom.springvaadin.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import es.lobocom.springvaadin.spring.user.UserRepository;





@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private static final String LOGIN_PROCESSING_URL = "/login";
	private static final String LOGIN_FAILURE_URL = "/login?error";
	private static final String LOGIN_URL = "/login";
	private static final String LOGOUT_SUCCESS_URL = "/";
	
//	private final UserDetailsService userDetailsService;

	@Autowired
	private PasswordEncoder passwordEncoder;
	
/*	
	@Autowired
	public SecurityConfiguration(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}	
*/	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
	public es.lobocom.springvaadin.spring.user.User currentUser(UserRepository userRepository) {
	    return userRepository.findByEmailIgnoreCase(SecurityUtils.getUsername());
	}
	
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		
		auth.inMemoryAuthentication()
		.withUser("buzz")
		.password(passwordEncoder().encode("infinito"))
		.authorities("ROLE_USER");
	}


	
	
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{

		http.csrf().disable()
        .authorizeRequests()
        /*
        .antMatchers("/VAADIN/**", "/HEARTBEAT/**", "/UIDL/**", "/resources/**"
                , "/login", "/login**", "/login/**", "/manifest.json", "/icons/**", "/images/**",
                // (development mode) static resources
                "/frontend/**",
                // (development mode) webjars
                "/webjars/**",
                // (development mode) H2 debugging console
                "/h2-console/**",
                // (production mode) static resources
                "/frontend-es5/**", "/frontend-es6/**").permitAll()
                */
		// Allow all flow internal requests.
		.requestMatchers(SecurityUtils::isFrameworkInternalRequest).permitAll()

		// Allow all requests by logged in users.
		.anyRequest().hasAnyAuthority(Role.getAllRoles())

		// Configure the login page.
		.and().formLogin().loginPage(LOGIN_URL).permitAll().loginProcessingUrl(LOGIN_PROCESSING_URL)
		.failureUrl(LOGIN_FAILURE_URL)
		
		// Register the success handler that redirects users to the page they last tried
		// to access
		.successHandler(new SavedRequestAwareAuthenticationSuccessHandler())

		// Configure logout
		.and().logout().logoutSuccessUrl(LOGOUT_SUCCESS_URL);
		
		/*
		http
		.csrf().disable()
        .exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")).accessDeniedPage("/accessDenied")
        .and().authorizeRequests()
        .antMatchers("/VAADIN/**", "/PUSH/**", "/UIDL/**", "/login", "/login/**", "/error/**", "/accessDenied/**", "/vaadinServlet/**").permitAll()
        .antMatchers("/authorized", "/**").fullyAuthenticated();
*/

/*		
		
		.authorizeRequests()
		.antMatchers("/")
		.hasRole("USER")
		//.antMatchers("/","/**").permitAll()
		;
*/		
	}
	
	
	@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
                // Vaadin Flow static resources
                "/VAADIN/**",

                // the standard favicon URI
                "/favicon.ico",

                // web application manifest
                "/manifest.json",

                // icons and images
                "/icons/**",
                "/images/**",

                // (development mode) static resources
                "/frontend/**",

                // (development mode) webjars
                "/webjars/**",

                // (development mode) H2 debugging console
                "/h2-console/**",

                // (production mode) static resources
                "/frontend-es5/**", "/frontend-es6/**");
    }


	
	
	
	
	

}
