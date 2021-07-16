package com.milo.barai.user.auth.controller;

import com.milo.barai.user.auth.dto.UserTokenDTO;
import com.milo.barai.user.auth.dto.LoginRequestDTO;
import com.milo.barai.user.auth.dto.RegistrationRequestDTO;
import com.milo.barai.user.auth.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api/auth/users/")
public class UserAuthController {

    private final AuthService service;

    @Autowired
    public UserAuthController(AuthService service) {
        this.service = service;
    }


    @PostMapping("signup")
    public void signup(@RequestBody RegistrationRequestDTO registrationRequestDTO){
        log.debug("signup, called.");
        service.signup(registrationRequestDTO);
    }

    //Should preferably be a put mapping as it makes changes in the DB
    //Currently set to get to be able to verify with just a basic browser.
    @GetMapping("verification/{token}")
    public void verifyUser(@PathVariable("token") String token){
        service.verifyUser(token);
    }

    @PostMapping("login")
    public UserTokenDTO login(@Valid @RequestBody LoginRequestDTO loginRequest) {
        return service.login(loginRequest);
    }

    @PostMapping("tokens/refresh")
    public UserTokenDTO refreshToken(@RequestBody UserTokenDTO userTokenDTO) {
        return service.refreshToken(userTokenDTO);
    }

}
