package com.example.controller;

import com.example.exception.UserAlreadyExistException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.NoSuchElementException;

import static org.springframework.http.ResponseEntity.badRequest;

@ControllerAdvice
public class ExceptionController {
    final Logger logger = LoggerFactory.getLogger(ExceptionController.class);

    @ExceptionHandler(value = {NoSuchElementException.class, MethodArgumentNotValidException.class, UserAlreadyExistException.class})
    public ResponseEntity<?> userNotFound(Exception ex) {
        logger.error(ex.getMessage());
        return badRequest().body(ex.getMessage());
    }

    @ExceptionHandler(value = {MissingRequestCookieException.class})
    public ResponseEntity<?> cookieNotFound(Exception ex) {
        logger.error(ex.getMessage());
        return ResponseEntity.status(401).build();
    }
}