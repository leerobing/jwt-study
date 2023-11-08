package com.example.jwtstudy.service;

import com.example.jwtstudy.controller.LoginForm;
import com.example.jwtstudy.controller.SignupForm;
import com.example.jwtstudy.entity.Users;
import com.example.jwtstudy.repository.UserRepository;
import com.example.jwtstudy.security.jwt.JwtToken;
import com.example.jwtstudy.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {


    private final BCryptPasswordEncoder encoder;
    private final UserRepository repository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;



    public JwtToken login(LoginForm loginForm) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginForm.getUsername(),loginForm.getPassword());

        // 검증
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 검증된 인증 정보로 JWT 토큰 생성
        JwtToken token = jwtTokenProvider.generateToken(authentication);

        return token;
    }

    public Long signup(SignupForm signupForm) {
        boolean check = checkEmailExists(signupForm.getEmail());

        if (check) {
            throw new IllegalArgumentException("이미 존재하는 유저입니다.");
        }

        String encPwd = encoder.encode(signupForm.getPassword());

        Users user = repository.save(signupForm.toEntity(encPwd));

        if(user!=null) {
            return user.getId();
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }

    public boolean checkEmailExists(String email) {
        return repository.existsUsersByEmail(email);
    }

}