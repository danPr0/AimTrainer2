package com.example.controller;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

//@EnableWebMvc
@ControllerAdvice
public class ExceptionController extends ResponseEntityExceptionHandler {
//    @ModelAttribute
//    public void populateModel(Model model) {
//        model.addAttribute("usernameNotFound");
//    }

    @ExceptionHandler(UsernameNotFoundException.class)
    protected String handleUsernameNotFound(UsernameNotFoundException ex) {
        System.out.print("NO");
        //model.addAttribute("usernameNotFound", ex.getMessage());
        return "index";
    }
}
