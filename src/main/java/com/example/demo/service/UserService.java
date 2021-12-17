package com.example.demo.service;

import com.example.demo.model.User;
import java.util.List;

public interface UserService {
    User findByUsername(String name);
    User findById(Long id);
    void save(User user);
    List<User> findAllByStatusTrueAndRole_IdRole(Long id);
    boolean existsByUsername(String userName);
}
