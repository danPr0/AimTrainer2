package com.example.repository;

import com.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
//    List<User> findUserByUsernameEndsWith(String username);

//    Optional<User> findUserByUsername(String username);

    Boolean existsByUsername(String username);
}

