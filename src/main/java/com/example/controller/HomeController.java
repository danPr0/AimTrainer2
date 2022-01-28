package com.example.controller;

import com.example.entity.User;
import org.springframework.http.HttpRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/")
public class HomeController {
    @PostMapping
    ResponseEntity<String> result(@RequestParam("result") String result) {
        if (result.equals("error"))
            return ResponseEntity.ok().body("unconfirmed");
        else return ResponseEntity.ok().body("confirmed");
    }
}
