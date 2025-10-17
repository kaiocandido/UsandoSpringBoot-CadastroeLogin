package com.example.login_auth_api.controllers;

import com.example.login_auth_api.domain.user.User;
import com.example.login_auth_api.dto.LoginResquestDTO;
import com.example.login_auth_api.dto.RegisterResquestDTO;
import com.example.login_auth_api.dto.ResponseDTO;
import com.example.login_auth_api.repositorys.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @RequestMapping("/login")
    public ResponseEntity login(@RequestBody LoginResquestDTO body){
        User user = this.repository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User not found"));
        if(passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.allocateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }


    @RequestMapping("/register")
    public ResponseEntity register(@RequestBody RegisterResquestDTO body){
        Optional<User> user = this.repository.findByEmail(body.email());
        if (user.isEmpty())){
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.repository.save(newUser);

            String token = this.tokenService.allocateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));

        }
        return ResponseEntity.badRequest().build();
    }


}
