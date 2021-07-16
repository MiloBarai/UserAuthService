package com.milo.barai.user.auth.service.impl;

import com.milo.barai.user.auth.entity.User;
import com.milo.barai.user.auth.exception.UserAuthException;
import com.milo.barai.user.auth.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

import static com.milo.barai.user.auth.exception.UserAuthErrorCode.NOT_FOUND;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepo;

    public UserDetailsServiceImpl(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> oUser = userRepo.findByUsername(username);
        User user = oUser.orElseThrow(() -> new UserAuthException(NOT_FOUND, "User not found."));

        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                                                                      user.getPassword(),
                                                                      Collections.singletonList(new SimpleGrantedAuthority("USER")));
    }
}
