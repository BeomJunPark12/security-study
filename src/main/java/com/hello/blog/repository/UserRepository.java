package com.hello.blog.repository;

import com.hello.blog.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    // select * from user where username = ?
    User findByUsername(String username);
}
