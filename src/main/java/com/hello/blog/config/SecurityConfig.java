package com.hello.blog.config;

import com.hello.blog.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RequiredArgsConstructor
@EnableWebSecurity  // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)  // secured 어노테이션 활성화
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean   // 해당 메서드의 리턴되는 오브젝트를 Ioc로 등록해준다
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()    // 인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")  // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행해준다.
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")   // 구글 로그인이 완료되면 후처리가 필요함, (엑세스토큰+사용자프로필정보 o)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);


    }
}
