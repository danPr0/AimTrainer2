package com.example.exception;

public class UserAlreadyExistException extends Exception {
    public UserAlreadyExistException(String msg) {
        super(msg);
    }
}
