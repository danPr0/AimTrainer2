package com.example.controller;

import com.example.entity.User;
import com.example.rest.RefreshTokenRequest;
import org.springframework.http.HttpRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/")
public class HomeController {
    @PostMapping
    void result(@RequestBody RefreshTokenRequest data) {
        System.out.println(SecurityContextHolder.getContext().getAuthentication().toString());
        System.out.println(data.getRefreshToken());
//        if (result.equals("error"))
//            return ResponseEntity.ok().body("unconfirmed");
//        else return ResponseEntity.ok().body("confirmed");
    }
}
