package com.milo.barai.user.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public final UserDetailsService userDetailsService;
    public final JwtAuthenticationFilter jwtAuthFilter;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService,
                          JwtAuthenticationFilter jwtAuthFilter){
        this.userDetailsService = userDetailsService;
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
            .disable()
            .authorizeRequests()
            //Allow anything under auth to pass.
            .antMatchers("/api/auth/**")
            .permitAll()
            //Authenticate everything else.
            .anyRequest()
            .authenticated();
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    /*
     * //Commented out since it seems like the passwordEncoder is already picked up.
     * @Autowired
     * public void configureGlobal(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
     *    authenticationManagerBuilder.userDetailsService(userDetailsService)
     *                               .passwordEncoder(new BCryptPasswordEncoder());
     * }
     */
}
