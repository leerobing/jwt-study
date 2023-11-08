package com.example.jwtstudy.controller;

import com.example.jwtstudy.entity.Role;
import com.example.jwtstudy.entity.Users;
import lombok.Getter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@Getter
public class SignupForm {
    @NotBlank(message = "이름을 입력해주세요.")
    private String name;
    @NotBlank(message = "이메일 주소를 입력해주세요.")
    @Email(message = "올바른 형식의 이메일 주소를 입력해주세요.")
    private String email;
    @NotBlank(message = "비밀번호를 입력해주세요.")
    private String password;

    public Users toEntity(String encPwd) {
        return Users.builder()
                .name(name)
                .email(email)
                .password(encPwd)
                .role(Role.USER)
                .build();
    }
}