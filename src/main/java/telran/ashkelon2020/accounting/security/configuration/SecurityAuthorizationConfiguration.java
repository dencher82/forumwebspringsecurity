package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true, securedEnabled = true, prePostEnabled = true) // three variants
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/account/register");

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic(); // Basic Auth
		http.csrf().disable(); // cross site request forgery (межсайтовая подделка запроса) - allow all
								// requests (not only GET) without authorization
//		http.authorizeRequests().anyRequest().permitAll(); // allow all requests
		http.authorizeRequests()
				.antMatchers(HttpMethod.GET).permitAll()				
//		/account		
				.antMatchers(HttpMethod.PUT,"/account/user/{login}**")
					.access("#login==authentication.name and hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.DELETE,"/account/user/{login}**")
					.access("#login==authentication.name")
				.antMatchers("/account/user/{login}/role/{role}**").hasRole("ADMIN")
				.antMatchers("/account/password**").authenticated()
//		/forum
				.antMatchers("/account/login**", "/forum/post/{author}**")
					.access("hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.DELETE, "/forum/post/{id}**")
					.access("hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and (@customSecurity.checkPostAuthority(#id, authentication.name) "
							+ "or hasRole('MODERATOR')) "
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.PUT, "/forum/post/{id}**")
					.access("hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and (@customSecurity.checkPostAuthority(#id, authentication.name) "
							+ "or hasRole('MODERATOR'))"
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.PUT, "/forum/post/{id}/like**")
					.access("hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}**")
					.access("hasAnyRole('ADMIN', 'MODERATOR', 'USER') "
							+ "and @customSecurity.checkExpDate(authentication.name)")
				.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll() // ** - allow operate with and without '/'
				
				.anyRequest().authenticated();

	}

}
