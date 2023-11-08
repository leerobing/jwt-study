package com.example.jwtstudy.controller;


import com.example.jwtstudy.security.jwt.JwtToken;
import com.example.jwtstudy.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;


    @PostMapping("/login")
    public ResponseEntity<JwtToken> loginSuccess(@RequestBody LoginForm loginForm) {
        JwtToken token = userService.login(loginForm);
        return ResponseEntity.ok(token);
    }
    @PostMapping("/signup")
    public Long signup(@RequestBody SignupForm signupForm) {
        return userService.signup(signupForm);
    }

    @GetMapping("/signup/check/{email}/exists")
    public ResponseEntity<Boolean> checkEmailDuplicate(@PathVariable String email) {
        return ResponseEntity.ok(userService.checkEmailExists(email));
    }
}
