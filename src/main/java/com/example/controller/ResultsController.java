package com.example.controller;

import com.example.entity.User;
import com.example.model.Results;
import com.example.rest.SaveResultRequest;
import com.example.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class ResultsController {
    private final UserService userService;

    public ResultsController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/save-result")
    public void saveResult(@RequestBody SaveResultRequest data) {
        User user = userService.findUserByUsername(SecurityContextHolder.getContext().getAuthentication().getName()).orElseThrow();
        userService.saveResult(user, data.getResult(), data.getSize());
    }

    @GetMapping("/get-results")
    public ResponseEntity<?> getResults() {
        List<Results> results = new ArrayList<>();
        List<User> users = userService.getUsers();

        for (User user : users) {
            results.add(new Results(user.getUsername(), user.getSmResult(), user.getMdResult(), user.getLgResult()));
        }
        return ResponseEntity.ok().body(results);
    }
}
