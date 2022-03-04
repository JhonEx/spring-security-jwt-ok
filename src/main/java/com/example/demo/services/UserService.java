package com.example.demo.services;


import com.example.demo.domain.Role;
import com.example.demo.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User userDTO);
    Role saveRole(Role roleDTO);
    void addRoleToUser(String username, String roleName);
    User getUser(String userName);
    List<User> getUsers();
}
