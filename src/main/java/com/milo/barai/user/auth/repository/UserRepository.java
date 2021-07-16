package com.milo.barai.user.auth.repository;

import com.milo.barai.user.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
        Optional<User> findByUsername(String username);
        Optional<User> findByEmail(String email);
}
