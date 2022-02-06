package guru.sfg.brewery.config;

import net.bytebuddy.asm.Advice;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    // because of this method, noop can be removed!
    PasswordEncoder passwordEncoder() {
        // return NoOpPasswordEncoder.getInstance(); // using NoOp
        // return new LdapShaPasswordEncoder(); // using for LDAP
        // return new SCryptPasswordEncoder(); // using for SHA-256
        return new BCryptPasswordEncoder(); // using BCrypt
        // return new BCryptPasswordEncoder(16); // using BCrypt encoding strength of 16
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }

    /*
    instead of this one, much nicer solution bellow!!!
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();

        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }
    */

    // Fluent API bellow:
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{noop}guru") // with {noop} I solve PasswordEncoder problem, that says mapped for id "null" as a failure message!
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{noop}password") // using {noop} here as well! now it stores just as a text (we correct it later! - wrong solution)
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{noop}tiger")
                .roles("CUSTOMER");
        // these are two different way to do!
        auth.inMemoryAuthentication().withUser("Csaba79-coder").password("{noop}csaba").roles("ADMIN");
    }
    */

    /* @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("guru") // with {noop} I solve PasswordEncoder problem, that says mapped for id "null" as a failure message!
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("password") // using {noop} here as well! now it stores just as a text (we correct it later! - wrong solution)
                .roles("USER")
                .and()
                .withUser("scott")
                .password("tiger")
                .roles("CUSTOMER");
        // these are two different way to do!
        auth.inMemoryAuthentication().withUser("Csaba79-coder").password("csaba").roles("ADMIN");
    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("guru") // with {noop} I solve PasswordEncoder problem, that says mapped for id "null" as a failure message!
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("$2a$10$4TgUFqVrjPGEbVJn1JZv5.hneRtyujEeb1qvy2IDoclfDJYpw/FqG") // using {noop} here as well! now it stores just as a text (we correct it later! - wrong solution)
                .roles("USER")
                .and()
                .withUser("scott")
                .password("tiger")
                .roles("CUSTOMER");
        // these are two different way to do!
        auth.inMemoryAuthentication().withUser("Csaba79-coder").password("csaba").roles("ADMIN");
    }
}