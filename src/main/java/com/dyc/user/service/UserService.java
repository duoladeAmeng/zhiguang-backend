package com.dyc.user.service;

import com.dyc.user.domain.User;

import java.util.Optional;

public interface UserService {
    Optional<User> findByPhone(String phone);

    Optional<User> findByEmail(String email);

    Optional<User> findById(long id);

    boolean existsByPhone(String phone);

    boolean existsByEmail(String email);

    User createUser(User user);

    void updatePassword(User user);
}
