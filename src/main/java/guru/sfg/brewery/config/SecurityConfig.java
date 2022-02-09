package guru.sfg.brewery.config;

import guru.sfg.brewery.security.JpaUserDetailsService;
import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // this is the inmemory authentication manager
    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager) {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }

    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager){
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    /*
    // Configure the one bellow to use RestHeaderAuthFilter in our config!
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(restHeaderAuthFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .csrf().disable();

        http
                .addFilterBefore(restUrlAuthFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class);

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() // do not use for production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll()
                            .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();

        //h2 console config
        http
                .headers().frameOptions().sameOrigin();
    }
    */

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic()
                .and().csrf().disable();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    // because of this method, noop can be removed!
    PasswordEncoder passwordEncoder() {
        // return NoOpPasswordEncoder.getInstance(); // using NoOp
        // return new LdapShaPasswordEncoder(); // using for LDAP
        // return new SCryptPasswordEncoder(); // using for SHA-256
        // return new BCryptPasswordEncoder(); // using BCrypt
        // return new BCryptPasswordEncoder(16); // using BCrypt encoding strength of 16
        // return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // using for delegating password encoder
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /*
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
    */

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

    /*@Override
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
    }*/

    /* // Commented because of JPA!!!
    @Override // for delegating password encoder
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                // BCrypt encoding
                .password("{bcrypt}$2a$10$7tYAvVL2/KwcQTcQywHIleKueg4ZK7y7d44hKyngjTwHCDlesxdla") // with {noop} I solve PasswordEncoder problem, that says mapped for id "null" as a failure message!
                .roles("ADMIN")
                .and()
                .withUser("user")
                // SHA-256 encoding
                .password("{sha256}4021d8f587f1eb17f8bf1edf3c0d4aa3f846d13e7469adbc197fc1f919df8b50735ac9b4da8f9239") // using {noop} here as well! now it stores just as a text (we correct it later! - wrong solution)
                .roles("USER")
                .and()
                .withUser("scott")
                // LDAP encoding
                .password("{ldap}{SSHA}h+Zp3jU7PL0VHNDd+n4aPafxlL4pLYiaixNZjw==")
                .roles("CUSTOMER");
        // these are two different way to do!
        auth.inMemoryAuthentication().withUser("Csaba79-coder").password("csaba").roles("ADMIN");
    }*/

    /*
    // instead of these methods we use @Transactional in SecurityConfig!
    @Autowired
    JpaUserDetailsService jpaUserDetailsService;

    @Override

        // if we have more than one UserDetailsService!
        auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());
    }
    */
}