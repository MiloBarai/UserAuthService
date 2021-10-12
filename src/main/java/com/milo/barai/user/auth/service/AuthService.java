package com.milo.barai.user.auth.service;

import com.milo.barai.user.auth.dto.ResendVerificationRequestDTO;
import com.milo.barai.user.auth.dto.UserTokenDTO;
import com.milo.barai.user.auth.dto.LoginRequestDTO;
import com.milo.barai.user.auth.dto.RegistrationRequestDTO;

public interface AuthService {
    void signup(RegistrationRequestDTO registrationRequestDTO);
    void resendVerification(ResendVerificationRequestDTO resendVerificationRequestDTO);
    void verifyUser(String token);
    UserTokenDTO login(LoginRequestDTO loginRequest);
    UserTokenDTO refreshUserJWT(UserTokenDTO userTokenDTO);
}
