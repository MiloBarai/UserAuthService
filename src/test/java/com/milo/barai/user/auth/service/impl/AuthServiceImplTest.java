package com.milo.barai.user.auth.service.impl;

import com.milo.barai.user.auth.dto.RegistrationRequestDTO;
import com.milo.barai.user.auth.entity.User;
import com.milo.barai.user.auth.entity.VerificationToken;
import com.milo.barai.user.auth.exception.UserAuthException;
import com.milo.barai.user.auth.repository.UserRepository;
import com.milo.barai.user.auth.repository.VerificationTokenRepository;
import com.milo.barai.user.auth.security.JwtUtils;
import com.milo.barai.user.auth.service.MailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthServiceImplTest {

    private AuthServiceImpl service;
    private UserRepository mUserRepository;
    private VerificationTokenRepository mTokenRepository;
    private MailService mMailService;

    @BeforeEach
    void init() {
        mUserRepository = mock(UserRepository.class);
        mTokenRepository = mock(VerificationTokenRepository.class);
        mMailService = mock(MailService.class);

        AuthenticationManager mAuthManager = mock(AuthenticationManager.class);

        when(mUserRepository.findByUsername("alreadyRegistered")).thenReturn(Optional.of(User.builder()
                                                                                             .username("alreadyRegistered")
                                                                                             .email("alreadyRegistered@example.com")
                                                                                             .password("123")
                                                                                             .build()));

        when(mUserRepository.findByEmail("alreadyRegistered@example.com")).thenReturn(Optional.of(User.builder()
                                                                                                      .username("alreadyRegistered")
                                                                                                      .email("alreadyRegistered@example.com")
                                                                                                      .password("123")
                                                                                                      .build()));

        JwtUtils jwtUtils = new JwtUtils("test", 90000L, 90000L);

        service = new AuthServiceImpl(NoOpPasswordEncoder.getInstance(),
                                      mUserRepository,
                                      mMailService,
                                      mTokenRepository,
                                      mAuthManager,
                                      jwtUtils,
                                      4);
    }

    @Test
    void signup() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "randomPassword", "someMail@example.com");
        service.signup(registration);


        //Validate that the correct information is sent to the DB.
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(mUserRepository, times(1)).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();
        assertThat(capturedUser.getUsername()).isEqualTo("newUser");
        assertThat(capturedUser.getPassword()).isEqualTo("randomPassword");
        assertThat(capturedUser.getEmail()).isEqualTo("someMail@example.com");


        //Validate that the verification token is for the correct user
        ArgumentCaptor<VerificationToken> verificationCaptor = ArgumentCaptor.forClass(VerificationToken.class);
        verify(mTokenRepository, times(1)).save(verificationCaptor.capture());
        assertThat(verificationCaptor.getValue().getUser().getUsername()).isEqualTo("newUser");

        //Assert that the correct token is sent in mail to the correct user
        ArgumentCaptor<User> mailUserCaptor = ArgumentCaptor.forClass(User.class);
        String verificationToken = verificationCaptor.getValue().getToken();
        verify(mMailService, times(1)).sendVerificationMail(mailUserCaptor.capture(), eq(verificationToken));
        assertThat(mailUserCaptor.getValue().getEmail()).isEqualTo("someMail@example.com");
    }

    @Test
    void signupEmptyMail() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "randomPassword", "");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Email may not be blank");
    }

    @Test
    void signupBlankMail() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "randomPassword", " \n");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Email may not be blank");
    }

    @Test
    void signupEmptyUsername() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("", "randomPassword", "someMail@example.com");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Username may not be blank");
    }

    @Test
    void signupBlankUsername() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO(" \n", "randomPassword", "someMail@example.com");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Username may not be blank");
    }

    @Test
    void signupEmptyPassword() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "", "someMail@example.com");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Password may not be blank");
    }

    @Test
    void signupBlankPassword() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", " \n", "someMail@example.com");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Password may not be blank");
    }


    @Test
    void signupInvalidMail() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "randomPassword", "foo");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Email: foo, is invalid");
    }

    @Test
    void signupInvalidPassword() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "foo", "someMail@example.com");
        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.signup(registration))
                                                          .withMessage("400, Password must be equal or longer than: 4");
    }

    @Test
    void signupMinimalPassword() {
        RegistrationRequestDTO registration = new RegistrationRequestDTO("newUser", "fooo", "someMail@example.com");
        service.signup(registration);
    }

    @Test
    void verifyUser() {
        String token = "testToken1";
        User tokenUser = User.builder()
                             .enabled(false)
                             .username("alreadyRegistered")
                             .email("alreadyRegistered@example.com")
                             .password("123")
                             .build();

        when(mTokenRepository.findByToken(token)).thenReturn(Optional.of(VerificationToken.builder()
                                                                                          .token("testToken1")
                                                                                          .id(1L)
                                                                                          .user(tokenUser)
                                                                                          .expiryDate(new Date(System.currentTimeMillis() + 900000))
                                                                                          .build()));

        service.verifyUser(token);
        assertThat(tokenUser.isEnabled()).isEqualTo(true);
        verify(mUserRepository, times(1)).save(tokenUser);
    }

    @Test
    void verifyUserExpiredToken() {
        String token = "testToken1";
        when(mTokenRepository.findByToken(token)).thenReturn(Optional.of(VerificationToken.builder()
                                                                                          .token("testToken1")
                                                                                          .id(1L)
                                                                                          .user(User.builder()
                                                                                                    .enabled(false)
                                                                                                    .username("alreadyRegistered")
                                                                                                    .email("alreadyRegistered@example.com")
                                                                                                    .password("123")
                                                                                                    .build())
                                                                                          .expiryDate(new Date(System.currentTimeMillis() - 900000))
                                                                                          .build()));

        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.verifyUser(token))
                                                          .withMessage("401, Expired Token used");
    }

    @Test
    void verifyUserTokenNotFound() {
        String token = "testToken1";
        when(mTokenRepository.findByToken(token)).thenReturn(Optional.empty());

        assertThatExceptionOfType(UserAuthException.class).isThrownBy(() -> service.verifyUser(token))
                                                          .withMessage("400, Invalid Token");
    }

    //TODO: Add tests for login & refresh token.

    @Test
    void login() {
    }

    @Test
    void refreshToken() {
    }
}