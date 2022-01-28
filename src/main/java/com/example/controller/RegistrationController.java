package com.example.controller;

import com.example.entity.User;
import com.example.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(value = "/registration")
public class RegistrationController {
    private final UserService userService;

    public RegistrationController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping()
    public ResponseEntity<String> addUser(@RequestBody User userForm) {
        if (!userForm.getPassword().equals(userForm.getPasswordConfirm()))
            return ResponseEntity.ok().body("Passwords mismatch");

        if (!userService.saveUser(userForm)){
            return ResponseEntity.ok().body("The user with this name is already exist!");
        }

        return ResponseEntity.ok().body("success");
    }
}
