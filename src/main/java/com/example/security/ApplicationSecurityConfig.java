package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("api/**").hasRole(STUDENT.name())
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login").permitAll()
        .passwordParameter("password")
        .usernameParameter("username")
        .defaultSuccessUrl("/courses", true)
        .and()
        .rememberMe()
            .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
            .key("quite_secure_huh?x*^+3ER=p4bGp7s22_ffh9cqYwyc6YAa9H2x")
            .rememberMeParameter("remember-me")
        .and()
        .logout()
            .logoutUrl("/logout")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
            .clearAuthentication(true)
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID", "remember-me")
            .logoutSuccessUrl("/login");

  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails annaUser =
        User.builder()
            .username("anna")
            .password(passwordEncoder.encode("pass"))
            .authorities(STUDENT.getGrantedAuthorities())
            // .roles(STUDENT.name()) // ROLE_STUDENT
            .build();

    UserDetails lindaUser =
        User.builder()
            .username("linda")
            .password(passwordEncoder.encode("pass"))
            .authorities(ADMIN.getGrantedAuthorities())
            // .roles(ADMIN.name()) // ROLE_ADMIN
            .build();

    UserDetails tomUser =
        User.builder()
            .username("tom")
            .password(passwordEncoder.encode("pass"))
            .authorities(ADMINTRAINEE.getGrantedAuthorities())
            // .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
            .build();

    return new InMemoryUserDetailsManager(annaUser, lindaUser, tomUser);
  }
}
