package com.example.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
    //비밀번호를 해시화하여 저장함. 반복적인 해시를 적용하여 브루트포스 공격에 대한 저항력을 높임

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "join").permitAll()
                        //인증되지 않은 사용자도 위 경로에 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // /admin 경로에 대한 요청은 ADMIN 역할을 가진 사용자만 접근 가능
                        .anyRequest().authenticated());
                        //나머지 모든 요청은 인증된 사용자만 접근 가능 (로그인 된 사용자)

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                        // 인증 처리적 관점에서 세션을 생성하지 않음과 동시에 세션을 이용한 방식으로 인증을 처리하지 않겠다는 의미

        return http.build();
    }
}
