package com.milo.barai.user.auth.service.impl;

import com.google.common.collect.Maps;
import com.milo.barai.user.auth.dto.UserTokenDTO;
import com.milo.barai.user.auth.dto.LoginRequestDTO;
import com.milo.barai.user.auth.dto.RegistrationRequestDTO;
import com.milo.barai.user.auth.entity.User;
import com.milo.barai.user.auth.entity.VerificationToken;
import com.milo.barai.user.auth.exception.UserAuthException;
import com.milo.barai.user.auth.repository.UserRepository;
import com.milo.barai.user.auth.repository.VerificationTokenRepository;
import com.milo.barai.user.auth.security.JwtUtils;
import com.milo.barai.user.auth.service.AuthService;
import com.milo.barai.user.auth.service.MailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.milo.barai.user.auth.exception.UserAuthErrorCode.*;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final MailService mailService;
    private final AuthenticationManager authManager;
    private final JwtUtils jwtUtils;
    private final int minPasswordLength;


    @Autowired
    public AuthServiceImpl(PasswordEncoder passwordEncoder,
                           UserRepository userRepository,
                           MailService mailService,
                           VerificationTokenRepository tokenRepository,
                           AuthenticationManager authManager,
                           JwtUtils jwtUtils,
                           @Value("${validation.minimum.password.length}") int minPasswordLength) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.mailService = mailService;
        this.authManager = authManager;
        this.jwtUtils = jwtUtils;
        this.minPasswordLength = minPasswordLength;
    }

    @Override
    @Transactional
    public void signup(RegistrationRequestDTO registrationRequestDTO) {
        User user = User.builder()
                        .username(registrationRequestDTO.getUsername())
                        .email(registrationRequestDTO.getEmail())
                        .password(passwordEncoder.encode(registrationRequestDTO.getPassword()))
                        .createdAt(Date.from(Instant.now()))
                        .enabled(false)
                        .archived(false)
                        .build();

        log.debug("Attempting to create user");
        validateUserRegistry(registrationRequestDTO);

        userRepository.save(user);
        log.debug("User successfully created: {}", user.getId());

        //Save verification token of user.
        VerificationToken token = generateVerificationToken(user);
        tokenRepository.save(token);

        //Send verification mail
        mailService.sendVerificationMail(token.getUser(), token.getToken());
    }

    @Override
    @Transactional
    public void verifyUser(String stringToken) {
        log.debug("Attempting to verify user with token: {}", stringToken);
        VerificationToken token = tokenRepository.findByToken(stringToken)
                                                 .orElseThrow(() -> new UserAuthException(BAD_REQUEST, "Invalid Token"));

        if (token.getExpiryDate().toInstant().isBefore(Instant.now())) {
            throw new UserAuthException(UNAUTHORIZED, "Expired Token used");
        }

        User user = token.getUser();
        user.setEnabled(true);

        userRepository.save(user);
    }

    @Override
    public UserTokenDTO login(LoginRequestDTO loginRequest) {

        Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        //Confirm user logged in.
        SecurityContextHolder.getContext()
                             .setAuthentication(authentication);

        validateUser(loginRequest.getUsername());

        String token = jwtUtils.generateToken(Maps.newHashMap(), loginRequest.getUsername());
        return new UserTokenDTO(loginRequest.getUsername(), token);
    }

    @Override
    public UserTokenDTO refreshToken(UserTokenDTO userTokenDTO) {
        validateUser(userTokenDTO.getUsername());
        String refreshedToken = jwtUtils.refreshToken(userTokenDTO.getUsername(), userTokenDTO.getAuthenticationToken());
        return new UserTokenDTO(userTokenDTO.getUsername(), refreshedToken);
    }

    private VerificationToken generateVerificationToken(User user) {

        String verificationTokenString = UUID.randomUUID().toString();

        return VerificationToken.builder()
                                .token(verificationTokenString)
                                .user(user)
                                .expiryDate(Date.from(Instant.now()
                                                             .plus(2, ChronoUnit.DAYS)))
                                .build();
    }

    private void validateUserRegistry(RegistrationRequestDTO registration) {

        //Checking for blanks or null

        if (registration.getUsername().isEmpty() || registration.getUsername().isBlank()) {
            throw new UserAuthException(BAD_REQUEST, "Username may not be blank");
        }

        if (registration.getPassword().isEmpty() || registration.getPassword().isBlank()) {
            throw new UserAuthException(BAD_REQUEST, "Password may not be blank");
        }

        if (registration.getEmail().isEmpty() || registration.getEmail().isBlank()) {
            throw new UserAuthException(BAD_REQUEST, "Email may not be blank");
        }

        //Validating non null inputs

        if (registration.getPassword().length() < minPasswordLength) {
            throw new UserAuthException(BAD_REQUEST, "Password must be equal or longer than: " + minPasswordLength);
        }

        if (!isValidEmail(registration.getEmail())) {
            throw new UserAuthException(BAD_REQUEST, "Email: " + registration.getEmail() + ", is invalid");
        }

        //Checking for db duplicates

        Optional<User> oUser = userRepository.findByUsername(registration.getUsername());

        if (oUser.isPresent()) {
            throw new UserAuthException(BAD_REQUEST, "Username " + registration.getUsername() + " is already taken");
        }

        oUser = userRepository.findByEmail(registration.getEmail());

        if (oUser.isPresent()) {
            throw new UserAuthException(BAD_REQUEST, "Email " + registration.getEmail() + " already registered");
        }
    }

    private void validateUser(String username) {

        User user = userRepository.findByUsername(username)
                                  .orElseThrow(() -> new UserAuthException(NOT_FOUND, "User with username " + username + ", not found"));

        if (user.isArchived()) {
            throw new UserAuthException(BAD_REQUEST, "User with username " + user.getUsername() + ", has been archived");
        }

        if (!user.isEnabled()) {
            throw new UserAuthException(BAD_REQUEST, "User with username " + user.getUsername() + ", has not yet been activated");
        }
    }

    private boolean isValidEmail(String emailStr) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        return matcher.find();
    }
}
